//! Program state processor

use crate::{
    error::AudiusProgramError,
    instruction::{
        AddSenderArgs, CreateSenderArgs, InitRewardManagerArgs, Instructions, TransferArgs,
        VerifyTransferSignatureArgs,
    },
    is_owner,
    state::{RewardManager, SenderAccount, SignedPayload, VerifiedMessages},
    utils::*,
};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::next_account_info,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::IsInitialized,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, sysvar,
    sysvar::Sysvar,
};

/// Sender program account seed
pub const SENDER_SEED_PREFIX: &str = "S_";
/// Transfer program account seed
pub const TRANSFER_SEED_PREFIX: &str = "T_";
/// Transfer account space
pub const TRANSFER_ACC_SPACE: usize = 0;

/// Program state handler.
pub struct Processor;

impl Processor {
    /// Transfer all the SOL from source to receiver
    pub fn transfer_all(source: &AccountInfo, receiver: &AccountInfo) -> Result<(), ProgramError> {
        let mut from = source.try_borrow_mut_lamports()?;
        let mut to = receiver.try_borrow_mut_lamports()?;
        **to += **from;
        **from = 0;
        Ok(())
    }

    /// Process example instruction
    #[allow(clippy::too_many_arguments)]
    fn process_init_instruction<'a>(
        program_id: &Pubkey,
        reward_manager_info: &AccountInfo<'a>,
        token_account_info: &AccountInfo<'a>,
        mint_info: &AccountInfo<'a>,
        manager_info: &AccountInfo<'a>,
        authority_info: &AccountInfo<'a>,
        spl_token_info: &AccountInfo<'a>,
        rent: &AccountInfo<'a>,
        min_votes: u8,
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if reward_manager.is_initialized() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        let (base, _) = get_base_address(program_id, reward_manager_info.key);
        if base != *authority_info.key {
            return Err(ProgramError::InvalidAccountData);
        }

        invoke(
            &spl_token::instruction::initialize_account(
                &spl_token::id(),
                token_account_info.key,
                mint_info.key,
                &base,
            )?,
            &[
                spl_token_info.clone(),
                token_account_info.clone(),
                mint_info.clone(),
                authority_info.clone(),
                rent.clone(),
            ],
        )?;

        RewardManager::new(*token_account_info.key, *manager_info.key, min_votes)
            .serialize(&mut *reward_manager_info.data.borrow_mut())?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_create_sender<'a>(
        program_id: &Pubkey,
        eth_address: EthereumAddress,
        operator: EthereumAddress,
        reward_manager_info: &AccountInfo<'a>,
        manager_account_info: &AccountInfo<'a>,
        authority_info: &AccountInfo<'a>,
        funder_account_info: &AccountInfo<'a>,
        sender_info: &AccountInfo<'a>,
        _sys_prog_info: &AccountInfo<'a>,
        rent_info: &AccountInfo<'a>,
    ) -> ProgramResult {
        if !manager_account_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if !reward_manager.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        if reward_manager.manager != *manager_account_info.key {
            return Err(AudiusProgramError::IncorectManagerAccount.into());
        }

        let pair = get_address_pair(
            program_id,
            reward_manager_info.key,
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )?;
        if *sender_info.key != pair.derive.address {
            return Err(AudiusProgramError::IncorectSenderAccount.into());
        }

        let signature = &[&reward_manager_info.key.to_bytes()[..32], &[pair.base.seed]];

        let rent = Rent::from_account_info(rent_info)?;
        invoke_signed(
            &system_instruction::create_account_with_seed(
                funder_account_info.key,
                sender_info.key,
                &pair.base.address,
                pair.derive.seed.as_str(),
                rent.minimum_balance(SenderAccount::LEN),
                SenderAccount::LEN as _,
                program_id,
            ),
            &[
                funder_account_info.clone(),
                sender_info.clone(),
                authority_info.clone(),
            ],
            &[signature],
        )?;

        SenderAccount::new(*reward_manager_info.key, eth_address, operator)
            .serialize(&mut *sender_info.data.borrow_mut())?;

        Ok(())
    }

    fn process_delete_sender<'a>(
        _program_id: &Pubkey,
        reward_manager_info: &AccountInfo<'a>,
        manager_account_info: &AccountInfo<'a>,
        sender_info: &AccountInfo<'a>,
        refunder_account_info: &AccountInfo<'a>,
        _sys_prog: &AccountInfo<'a>,
    ) -> ProgramResult {
        if !manager_account_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        let sender = SenderAccount::try_from_slice(&sender_info.data.borrow())?;
        if sender.reward_manager != *reward_manager_info.key {
            return Err(AudiusProgramError::WrongRewardManagerKey.into());
        }

        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if reward_manager.manager != *manager_account_info.key {
            return Err(AudiusProgramError::IncorectManagerAccount.into());
        }

        Self::transfer_all(sender_info, refunder_account_info)?;

        Ok(())
    }

    /// Checks that the user signed message with his ethereum private key
    fn check_secp_signs(
        program_id: &Pubkey,
        reward_manager_info: &AccountInfo,
        instruction_info: &AccountInfo,
        expected_signers: Vec<&AccountInfo>,
        extraction_depth: usize,
        verifier: impl VerifierFn,
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if expected_signers.len() < reward_manager.min_votes as _ {
            return Err(AudiusProgramError::NotEnoughSigners.into());
        }

        let index = sysvar::instructions::load_current_index(&instruction_info.data.borrow());
        // instruction can't be first in transaction
        // because must follow after `new_secp256k1_instruction`
        if index == 0 {
            return Err(AudiusProgramError::Secp256InstructionMissing.into());
        }

        let secp_instructions = get_secp_instructions(index, extraction_depth, instruction_info)?;

        let (senders_eth_addresses, operators_set) =
            get_eth_addresses(program_id, reward_manager_info.key, expected_signers)?;

        verifier(secp_instructions, senders_eth_addresses, operators_set)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_add_sender<'a>(
        program_id: &Pubkey,
        reward_manager_info: &AccountInfo<'a>,
        authority_info: &AccountInfo<'a>,
        funder_info: &AccountInfo<'a>,
        new_sender_info: &AccountInfo<'a>,
        instructions_info: &AccountInfo<'a>,
        rent_info: &AccountInfo<'a>,
        signers_info: Vec<&AccountInfo>,
        eth_address: EthereumAddress,
        operator: EthereumAddress,
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if !reward_manager.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        let verifier = build_verify_secp_add_sender(reward_manager_info.key.clone(), eth_address);
        Self::check_secp_signs(
            program_id,
            &reward_manager_info,
            instructions_info,
            signers_info.clone(),
            signers_info.len(),
            verifier,
        )?;

        let pair = get_address_pair(
            program_id,
            reward_manager_info.key,
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )?;

        let signature = &[&reward_manager_info.key.to_bytes()[..32], &[pair.base.seed]];

        let rent = Rent::from_account_info(rent_info)?;
        invoke_signed(
            &system_instruction::create_account_with_seed(
                funder_info.key,
                &pair.derive.address,
                &pair.base.address,
                pair.derive.seed.as_str(),
                rent.minimum_balance(SenderAccount::LEN),
                SenderAccount::LEN as _,
                program_id,
            ),
            &[
                funder_info.clone(),
                new_sender_info.clone(),
                authority_info.clone(),
            ],
            &[signature],
        )?;

        SenderAccount::new(*reward_manager_info.key, eth_address, operator)
            .serialize(&mut *new_sender_info.data.borrow_mut())?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_verify_transfer_signature<'a>(
        program_id: &Pubkey,
        verified_messages_info: &AccountInfo<'a>,
        reward_manager_info: &AccountInfo<'a>,
        sender_info: &AccountInfo<'a>,
        funder_info: &AccountInfo<'a>,
        instruction_info: &AccountInfo<'a>,
        signed_payload: SignedPayload,
    ) -> ProgramResult {
        if !funder_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        is_owner!(
            *program_id,
            verified_messages_info,
            reward_manager_info,
            sender_info
        )?;

        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if !reward_manager.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        let sender_account = SenderAccount::try_from_slice(&sender_info.data.borrow())?;
        if !sender_account.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }
        if sender_account.eth_address != signed_payload.address {
            return Err(AudiusProgramError::IncorectSenderAccount.into());
        }
        assert_account_key(reward_manager_info, &sender_account.reward_manager)?;

        msg!("TS1");
        msg!("LEN {}", std::mem::size_of::<VerifiedMessages>());

        let mut verified_messages =
            VerifiedMessages::try_from_slice(&verified_messages_info.data.borrow())?;
        if verified_messages.is_initialized() {
            assert_account_key(reward_manager_info, &verified_messages.reward_manager)?;
        } else {
            verified_messages = VerifiedMessages::new(*reward_manager_info.key);
        }

        msg!("TS2");

        // Check signatures from prev instruction
        check_ethereum_sign(
            instruction_info,
            &signed_payload.address,
            &signed_payload.message,
        )?;

        verified_messages.add(signed_payload, sender_account.operator);
        // Check unique senders & operators
        assert_unique_senders(verified_messages.messages.clone())?;

        verified_messages.serialize(&mut *verified_messages_info.data.borrow_mut())?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_transfer<'a>(
        program_id: &Pubkey,
        verified_messages_info: &AccountInfo<'a>,
        reward_manager_info: &AccountInfo<'a>,
        reward_manager_authority_info: &AccountInfo<'a>,
        reward_token_source_info: &AccountInfo<'a>,
        reward_token_recipient_info: &AccountInfo<'a>,
        transfer_account_info: &AccountInfo<'a>,
        bot_oracle_info: &AccountInfo<'a>,
        payer_info: &AccountInfo<'a>,
        rent_info: &AccountInfo<'a>,
        transfer_data: TransferArgs,
    ) -> ProgramResult {
        let rent = &Rent::from_account_info(rent_info)?;

        is_owner!(
            *program_id,
            verified_messages_info,
            reward_manager_info,
            bot_oracle_info
        );

        let verified_messages =
            VerifiedMessages::try_from_slice(&verified_messages_info.data.borrow())?;
        assert_initialized(&verified_messages)?;

        let bot_oracle = SenderAccount::try_from_slice(&bot_oracle_info.data.borrow())?;
        assert_initialized(&bot_oracle)?;

        // Bot oracle reward manager should be correct
        assert_account_key(reward_manager_info, &bot_oracle.reward_manager)?;

        let message = [
            transfer_data.eth_recipient.as_ref(),
            b"_",
            transfer_data.amount.to_le_bytes().as_ref(),
            b"_",
            transfer_data.id.as_ref(),
            b"_",
            bot_oracle.eth_address.as_ref(),
        ]
        .concat();

        // Check messages and bot oracles
        assert_messages(&message, &verified_messages.messages)?;

        // Transfer reward tokens to user
        token_transfer(
            program_id,
            &reward_manager_info.key,
            reward_token_source_info,
            reward_token_recipient_info,
            reward_manager_authority_info,
            transfer_data.amount,
        )?;

        // Pack seeds
        let signers_seeds = &[
            TRANSFER_SEED_PREFIX.as_bytes().as_ref(),
            transfer_data.id.as_ref(),
        ];

        // Create deterministic account on-chain
        create_account(
            program_id,
            reward_manager_info.clone(),
            transfer_account_info.clone(),
            0,
            &[signers_seeds],
            rent,
        )?;

        Ok(())
    }

    /// Processes an instruction
    pub fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        input: &[u8],
    ) -> ProgramResult {
        let instruction = Instructions::try_from_slice(input)?;
        let account_info_iter = &mut accounts.iter();
        match instruction {
            Instructions::InitRewardManager(InitRewardManagerArgs { min_votes }) => {
                msg!("Instruction: InitRewardManager");

                let reward_manager = next_account_info(account_info_iter)?;
                let token_account = next_account_info(account_info_iter)?;
                let mint = next_account_info(account_info_iter)?;
                let manager = next_account_info(account_info_iter)?;
                let authority = next_account_info(account_info_iter)?;
                let _spl_token = next_account_info(account_info_iter)?;
                let rent = next_account_info(account_info_iter)?;

                Self::process_init_instruction(
                    program_id,
                    reward_manager,
                    token_account,
                    mint,
                    manager,
                    authority,
                    _spl_token,
                    rent,
                    min_votes,
                )
            }
            Instructions::CreateSender(CreateSenderArgs {
                eth_address,
                operator,
            }) => {
                msg!("Instruction: CreateSender");

                let reward_manager = next_account_info(account_info_iter)?;
                let manager_account = next_account_info(account_info_iter)?;
                let authority = next_account_info(account_info_iter)?;
                let funder_account = next_account_info(account_info_iter)?;
                let sender = next_account_info(account_info_iter)?;
                let sys_prog = next_account_info(account_info_iter)?;
                let rent = next_account_info(account_info_iter)?;

                Self::process_create_sender(
                    program_id,
                    eth_address,
                    operator,
                    reward_manager,
                    manager_account,
                    authority,
                    funder_account,
                    sender,
                    sys_prog,
                    rent,
                )
            }
            Instructions::DeleteSender => {
                msg!("Instruction: DeleteSender");

                let reward_manager = next_account_info(account_info_iter)?;
                let manager_account = next_account_info(account_info_iter)?;
                let sender = next_account_info(account_info_iter)?;
                let refunder = next_account_info(account_info_iter)?;
                let sys_prog = next_account_info(account_info_iter)?;

                Self::process_delete_sender(
                    program_id,
                    reward_manager,
                    manager_account,
                    sender,
                    refunder,
                    sys_prog,
                )
            }
            Instructions::AddSender(AddSenderArgs {
                eth_address,
                operator,
            }) => {
                msg!("Instruction: AddSender");

                let reward_manager = next_account_info(account_info_iter)?;
                let authority = next_account_info(account_info_iter)?;
                let funder = next_account_info(account_info_iter)?;
                let new_sender = next_account_info(account_info_iter)?;
                let instructions_info = next_account_info(account_info_iter)?;
                let rent = next_account_info(account_info_iter)?;
                let _system_program = next_account_info(account_info_iter)?;
                let signers = account_info_iter.collect::<Vec<&AccountInfo>>();

                Self::process_add_sender(
                    program_id,
                    reward_manager,
                    authority,
                    funder,
                    new_sender,
                    instructions_info,
                    rent,
                    signers,
                    eth_address,
                    operator,
                )
            }
            Instructions::VerifyTransferSignature(VerifyTransferSignatureArgs {
                signed_payload,
            }) => {
                msg!("Instruction: VerifyTransferSignature");

                let verified_messages = next_account_info(account_info_iter)?;
                let reward_manager = next_account_info(account_info_iter)?;
                let sender = next_account_info(account_info_iter)?;
                let funder = next_account_info(account_info_iter)?;
                let instructions_info = next_account_info(account_info_iter)?;
                let _system_program = next_account_info(account_info_iter)?;

                Self::process_verify_transfer_signature(
                    program_id,
                    verified_messages,
                    reward_manager,
                    sender,
                    funder,
                    instructions_info,
                    signed_payload,
                )
            }
            Instructions::Transfer(TransferArgs {
                amount,
                id,
                eth_recipient,
            }) => {
                msg!("Instruction: Transfer");

                let verified_messages_info = next_account_info(account_info_iter)?;
                let reward_manager_info = next_account_info(account_info_iter)?;
                let reward_manager_authority_info = next_account_info(account_info_iter)?;
                let reward_token_source_info = next_account_info(account_info_iter)?;
                let reward_token_recipient_info = next_account_info(account_info_iter)?;
                let transfer_account_info = next_account_info(account_info_iter)?;
                let bot_oracle_info = next_account_info(account_info_iter)?;
                let payer_info = next_account_info(account_info_iter)?;
                let _sysvar_rent = next_account_info(account_info_iter)?;
                let _token_program_id = next_account_info(account_info_iter)?;
                let _system_program_id = next_account_info(account_info_iter)?;

                Self::process_transfer(
                    program_id,
                    verified_messages_info,
                    reward_manager_info,
                    reward_manager_authority_info,
                    reward_token_source_info,
                    reward_token_recipient_info,
                    transfer_account_info,
                    bot_oracle_info,
                    payer_info,
                    _sysvar_rent,
                    TransferArgs {
                        amount,
                        id,
                        eth_recipient,
                    },
                )
            }
        }
    }
}

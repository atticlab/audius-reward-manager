//! Program state processor

use crate::{
    error::AudiusProgramError,
    instruction::{
        AddSenderArgs, CreateSenderArgs, InitRewardManagerArgs, Instructions, TransferArgs,
    },
    state::{RewardManager, SenderAccount, VerifiedMessage, VerifiedMessages},
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
    program_pack::{IsInitialized, Pack},
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
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

        if signers_info.len() < reward_manager.min_votes.into() {
            return Err(AudiusProgramError::NotEnoughSigners.into());
        }

        check_secp_add_sender(
            program_id,
            &reward_manager_info.key,
            instructions_info,
            signers_info.clone(),
            signers_info.len(),
            eth_address,
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
    ) -> ProgramResult {
        if !funder_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        assert_owned_by(verified_messages_info, program_id)?;
        assert_owned_by(reward_manager_info, program_id)?;
        assert_owned_by(sender_info, program_id)?;

        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if !reward_manager.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        let sender_account = SenderAccount::try_from_slice(&sender_info.data.borrow())?;
        if !sender_account.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }
        assert_account_key(reward_manager_info, &sender_account.reward_manager)?;

        let mut verified_messages =
            VerifiedMessages::unpack_unchecked(&verified_messages_info.data.borrow())?;
        if verified_messages.is_initialized() {
            assert_account_key(reward_manager_info, &verified_messages.reward_manager)?;
        } else {
            verified_messages = VerifiedMessages::new(*reward_manager_info.key);
        }

        // Check signatures from prev instruction
        let message = check_secp_verify_transfer(instruction_info, &sender_account.eth_address)?;

        verified_messages.add(VerifiedMessage {
            address: sender_account.eth_address,
            message,
            operator: sender_account.operator,
        });

        // Check unique senders & operators
        assert_unique_senders(&verified_messages.messages)?;

        VerifiedMessages::pack(verified_messages, *verified_messages_info.data.borrow_mut())?;

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

        assert_owned_by(verified_messages_info, program_id)?;
        assert_owned_by(reward_manager_info, program_id)?;
        assert_owned_by(bot_oracle_info, program_id)?;

        let verified_messages =
            VerifiedMessages::try_from_slice(&verified_messages_info.data.borrow())?;
        assert_initialized(&verified_messages)?;

        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        assert_initialized(&reward_manager)?;

        let bot_oracle = SenderAccount::try_from_slice(&bot_oracle_info.data.borrow())?;
        assert_initialized(&bot_oracle)?;

        // Bot oracle reward manager should be correct
        assert_account_key(reward_manager_info, &bot_oracle.reward_manager)?;

        // Check signs for minimum required votes
        if verified_messages.messages.len() != reward_manager.min_votes as usize {
            return Err(AudiusProgramError::NotEnoughSigners.into());
        }

        // Valid senders message
        let valid_message = [
            transfer_data.eth_recipient.as_ref(),
            b"_",
            transfer_data.amount.to_le_bytes().as_ref(),
            b"_",
            transfer_data.id.as_ref(),
            b"_",
            bot_oracle.eth_address.as_ref(),
        ]
        .concat();

        // Valid bot oracle message
        let valid_bot_oracle_message = [
            transfer_data.eth_recipient.as_ref(),
            b"_",
            transfer_data.amount.to_le_bytes().as_ref(),
            b"_",
            transfer_data.id.as_ref(),
        ]
        .concat();

        // Check messages and bot oracles
        assert_messages(
            &valid_message,
            &valid_bot_oracle_message,
            &bot_oracle.eth_address,
            &verified_messages.messages,
        )?;

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

        // Delete verified messages account
        let verified_messages_lamports = verified_messages_info.lamports();
        let payer_lamports = payer_info.lamports();

        **verified_messages_info.lamports.borrow_mut() = 0u64;
        **payer_info.lamports.borrow_mut() = payer_lamports
            .checked_add(verified_messages_lamports)
            .ok_or(AudiusProgramError::MathOverflow)?;

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
            Instructions::VerifyTransferSignature => {
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

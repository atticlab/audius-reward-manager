//! Program state processor

use crate::{
    error::AudiusProgramError,
    instruction::{Instructions, Transfer},
    state::{RewardManager, SenderAccount},
    utils::*,
};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    account_info::{next_account_info, next_account_infos},
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
pub const SENDER_SEED_PREFIX: &'static str = "S_";
/// Transfer program account seed
pub const TRANSFER_SEED_PREFIX: &'static str = "T_";

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

    fn process_create_sender<'a>(
        program_id: &Pubkey,
        eth_address: EthereumAddress,
        reward_manager_info: &AccountInfo<'a>,
        manager_account_info: &AccountInfo<'a>,
        authority_info: &AccountInfo<'a>,
        funder_account_info: &AccountInfo<'a>,
        sender_info: &AccountInfo<'a>,
        _sys_prog_info: &AccountInfo<'a>,
        rent_info: &AccountInfo<'a>,
    ) -> ProgramResult {
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
            &[SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()],
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

        SenderAccount::new(*reward_manager_info.key, eth_address)
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
    fn check_ethereum_sign(
        program_id: &Pubkey,
        reward_manager_info: &AccountInfo,
        instruction_info: &AccountInfo,
        expected_signers: Vec<&AccountInfo>,
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;

        if expected_signers.len() < reward_manager.min_votes as _ {
            return Err(AudiusProgramError::NotEnoughSenders.into());
        }

        let index = sysvar::instructions::load_current_index(&instruction_info.data.borrow());

        // instruction can't be first in transaction
        // because must follow after `new_secp256k1_instruction`
        if index == 0 {
            return Err(AudiusProgramError::Secp256InstructionMissing.into());
        }

        let secp_instructions =
            get_secp_instructions(index, expected_signers.len(), instruction_info)?;

        let senders_eth_addresses =
            get_eth_addresses(program_id, reward_manager_info.key, expected_signers)?;

        verify_secp_instructions(
            bot_oracle_data.eth_address,
            senders_eth_addresses,
            secp_instructions,
            transfer_data.clone(),
        )
    }

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
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if !reward_manager.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        Self::check_ethereum_sign(program_id, &reward_manager_info, instructions_info, signers_info);

        let pair = get_address_pair(
            program_id, 
            reward_manager_info.key, 
            &[SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()],
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

        SenderAccount::new(*reward_manager_info.key, eth_address)
            .serialize(&mut *new_sender_info.data.borrow_mut())?;

        Ok(())
    }

    fn process_transfer<'a>(
        program_id: &Pubkey,
        reward_manager: &AccountInfo<'a>,
        reward_manager_authority: &AccountInfo<'a>,
        recipient: &AccountInfo<'a>,
        vault_token_account: &AccountInfo<'a>,
        bot_oracle: &AccountInfo<'a>,
        funder: &AccountInfo<'a>,
        transfer_acc_to_create: &AccountInfo<'a>,
        instruction_info: &AccountInfo<'a>,
        transfer_data: Transfer,
        senders: Vec<AccountInfo<'a>>,
    ) -> ProgramResult {
        let reward_manager_data = RewardManager::try_from_slice(&reward_manager.data.borrow())?;
        if !reward_manager_data.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        let bot_oracle_data = SenderAccount::try_from_slice(&bot_oracle.data.borrow())?;
        if !bot_oracle_data.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        let generated_bot_oracle_key = get_address_pair(
            program_id,
            reward_manager.key,
            &[
                SENDER_SEED_PREFIX.as_ref(),
                bot_oracle_data.eth_address.as_ref(),
            ],
        )?;
        if generated_bot_oracle_key.derive.address != *bot_oracle.key {
            return Err(ProgramError::InvalidSeeds);
        }

        let generated_transfer_acc_to_create = get_address_pair(
            program_id,
            reward_manager.key,
            &[TRANSFER_SEED_PREFIX.as_ref(), transfer_data.id.as_ref()],
        )?;
        if generated_transfer_acc_to_create.derive.address != *transfer_acc_to_create.key {
            return Err(ProgramError::InvalidSeeds);
        }

        let generated_recipient_key = get_address_pair(
            program_id,
            reward_manager.key,
            &[transfer_data.eth_recipient.as_ref()],
        )?;
        if generated_recipient_key.derive.address != *recipient.key {
            return Err(AudiusProgramError::WrongRecipientKey.into());
        }

        Self::check_ethereum_sign(program_id, &reward_manager_data, instruction_info, senders);

        token_transfer(
            program_id,
            reward_manager.key,
            vault_token_account,
            recipient,
            reward_manager_authority,
            transfer_data.amount,
        )?;

        let mut seed = Vec::new();
        seed.extend_from_slice(TRANSFER_SEED_PREFIX.as_ref());
        seed.extend_from_slice(transfer_data.id.as_ref());

        create_account_with_seed(
            program_id,
            funder,
            transfer_acc_to_create,
            reward_manager_authority,
            reward_manager.key,
            seed.as_ref(),
            1,
            0,
            program_id,
        )
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
            Instructions::InitRewardManager { min_votes } => {
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
            Instructions::CreateSender { eth_address } => {
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
            Instructions::AddSender { eth_address } => {
                msg!("Instruction: AddSender");

                let reward_manager = next_account_info(account_info_iter)?;
                let authority = next_account_info(account_info_iter)?;
                let funder = next_account_info(account_info_iter)?;
                let new_sender = next_account_info(account_info_iter)?;
                let instructions_info = next_account_info(account_info_iter)?;
                let rent = next_account_info(account_info_iter)?;
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
                )
            }
            Instructions::Transfer {
                amount,
                id,
                eth_recipient,
            } => {
                msg!("Instruction: Transfer");

                let reward_manager = next_account_info(account_info_iter)?;
                let reward_manager_authority = next_account_info(account_info_iter)?;
                let recipient = next_account_info(account_info_iter)?;
                let vault_token_account = next_account_info(account_info_iter)?;
                let bot_oracle = next_account_info(account_info_iter)?;
                let funder = next_account_info(account_info_iter)?;
                let transfer_acc_to_create = next_account_info(account_info_iter)?;
                let instruction_info = next_account_info(account_info_iter)?;

                let senders =
                    next_account_infos(&mut account_info_iter.clone(), account_info_iter.count())?
                        .to_vec();

                Self::process_transfer(
                    program_id,
                    reward_manager,
                    reward_manager_authority,
                    recipient,
                    vault_token_account,
                    bot_oracle,
                    funder,
                    transfer_acc_to_create,
                    instruction_info,
                    Transfer {
                        amount,
                        id,
                        eth_recipient,
                    },
                    senders,
                )
            }
        }
    }
}

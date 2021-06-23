//! Program state processor

use crate::{instruction::Instructions, state::{RewardManager, SenderAccount}, utils::{get_address_pair, get_base_address}};
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
    system_instruction,
    sysvar::Sysvar,
};
use std::str;

/// Program state handler.
pub struct Processor;

impl Processor {
    /// Process example instruction
    fn process_init_instruction<'a>(
        program_id: &Pubkey,
        reward_manager_info: &AccountInfo<'a>,
        token_account_info: &AccountInfo<'a>,
        mint_info: &AccountInfo<'a>,
        manager_info: &AccountInfo<'a>,
        athority_info: &AccountInfo<'a>,
        spl_token_info: &AccountInfo<'a>,
        rent: &AccountInfo<'a>,
        min_votes: u8,
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if reward_manager.is_initialized() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        let (base, _) = get_base_address(reward_manager_info.key, program_id);
        if base != *athority_info.key {
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
                athority_info.clone(),
                rent.clone(),
            ],
        )?;

        RewardManager::new(*token_account_info.key, *manager_info.key, min_votes)
            .serialize(&mut *reward_manager_info.data.borrow_mut())?;
        
        Ok(())
    }

    fn process_create_sender<'a>(
        program_id: &Pubkey,
        eth_address: [u8; 20],
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
            msg!("Incorect account manager");
            todo!();
        }

        let pair = get_address_pair(program_id, reward_manager_info.key, eth_address)?;
        if *sender_info.key != pair.derive.address {
            msg!("Incorect sender account");
            todo!()
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

        SenderAccount::new(*manager_account_info.key, eth_address)
            .serialize(&mut *sender_info.data.borrow_mut())?;

        Ok(())
    }

    fn process_delete_sender<'a>(
        program_id: &Pubkey,
        authority_info: &AccountInfo<'a>,
        reward_manager_info: &AccountInfo<'a>,
        refunder_account_info: &AccountInfo<'a>,
        sender_info: &AccountInfo<'a>,
        sys_prog: &AccountInfo<'a>,
    ) -> ProgramResult {
        let sender_account = SenderAccount::try_from_slice(&sender_info.data.borrow())?;

        let pair = get_address_pair(program_id, reward_manager_info.key, sender_account.eth_address)?;

        let signature = &[&reward_manager_info.key.to_bytes()[..32], &[pair.base.seed]];

        invoke_signed(
            &system_instruction::transfer_with_seed(
                &pair.derive.address,
                authority_info.key,
                pair.derive.seed,
                program_id,
                refunder_account_info.key,
                sender_info.lamports(),
            ),
            &[
                sender_info.clone(),
                authority_info.clone(),
                refunder_account_info.clone(),
            ],
            &[signature],
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
            Instructions::InitRewardManager { min_votes } => {
                msg!("Instruction: InitRewardManager");

                let reward_manager = next_account_info(account_info_iter)?;
                let token_account = next_account_info(account_info_iter)?;
                let mint = next_account_info(account_info_iter)?;
                let manager = next_account_info(account_info_iter)?;
                let athority = next_account_info(account_info_iter)?;
                let _spl_token = next_account_info(account_info_iter)?;
                let rent = next_account_info(account_info_iter)?;

                Self::process_init_instruction(
                    program_id,
                    reward_manager,
                    token_account,
                    mint,
                    manager,
                    athority,
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
                let _manager_account = next_account_info(account_info_iter)?;
                let authority = next_account_info(account_info_iter)?;
                let sender = next_account_info(account_info_iter)?;
                let refunder = next_account_info(account_info_iter)?;
                let sys_prog = next_account_info(account_info_iter)?;

                Self::process_delete_sender(
                    program_id,
                    authority,
                    reward_manager,
                    refunder,
                    sender,
                    sys_prog,
                )
            }
        }
    }
}

//! Program state processor

use crate::{
    instruction::Instructions,
    state::{RewardManager, SenderAccount},
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
        rent: &AccountInfo<'a>,
        min_votes: u8,
    ) -> ProgramResult {
        let reward_manager = RewardManager::try_from_slice(&reward_manager_info.data.borrow())?;
        if reward_manager.is_initialized() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        let (authority, _) =
            Pubkey::find_program_address(&[reward_manager_info.key.as_ref()], program_id);
        if authority != *athority_info.key {
            return Err(ProgramError::InvalidAccountData);
        }

        invoke(
            &spl_token::instruction::initialize_account(
                &spl_token::id(),
                token_account_info.key,
                mint_info.key,
                &authority,
            )?,
            &[
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

        let (authority, base_seed) = Pubkey::find_program_address(&[&reward_manager_info.key.to_bytes()[..32]], program_id);

        let mut seed = Vec::new();
        seed.extend_from_slice(b"S_");
        seed.extend_from_slice(&eth_address.as_ref());
        let s_seed = str::from_utf8(seed.as_ref()).unwrap();
        let sender_address = Pubkey::create_with_seed(&authority, s_seed, &crate::id())?;
        if *sender_info.key != sender_address {
            msg!("Incorect sender account");
            todo!()
        }
        
        let signature = &[&reward_manager_info.key.to_bytes()[..32], &[base_seed]];

        let rent = Rent::from_account_info(rent_info)?;
        invoke_signed(
            &system_instruction::create_account_with_seed(
                funder_account_info.key,
                sender_info.key,
                authority_info.key,
                s_seed,
                rent.minimum_balance(SenderAccount::LEN),
                SenderAccount::LEN as _,
                &crate::id(),
            ),
            &[funder_account_info.clone(), sender_info.clone(), authority_info.clone()],
            &[signature],
        )?;
        
        SenderAccount::new(*manager_account_info.key, eth_address)
            .serialize(&mut *sender_info.data.borrow_mut())?;

        Ok(())
    }

    fn process_delete_sender<'a>(
        program_id: &Pubkey,
        _authority_info: &AccountInfo<'a>,
        reward_manager_info: &AccountInfo<'a>,
        refunder_account_info: &AccountInfo<'a>,
        sender_info: &AccountInfo<'a>,
    ) -> ProgramResult {
        let sender = SenderAccount::try_from_slice(&sender_info.data.borrow())?;
        let (authority, _) =
            Pubkey::find_program_address(&[reward_manager_info.key.as_ref()], program_id);
        let (_, seed) = Pubkey::find_program_address(
            &[&authority.to_bytes(), b"S_", sender.eth_address.as_ref()],
            program_id,
        );

        invoke_signed(
            &system_instruction::transfer(
                sender_info.key,
                &refunder_account_info.key,
                sender_info.lamports(),
            ),
            &[sender_info.clone(), refunder_account_info.clone()],
            &[&[&[seed]]],
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
                Self::process_delete_sender(program_id, authority, reward_manager, refunder, sender)
            }
        }
    }
}

//! Program state processor

use crate::{instruction::Instructions, state::RewardManager};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::next_account_info, account_info::AccountInfo, entrypoint::ProgramResult, msg,
    program::invoke, program_error::ProgramError, program_pack::IsInitialized, pubkey::Pubkey,
};

/// Program state handler.
pub struct Processor {}
impl Processor {
    /// Process example instruction
    pub fn process_init_instruction<'a>(
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
        }
    }
}

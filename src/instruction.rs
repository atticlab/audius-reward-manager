//! Instruction types

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar,
};

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum Instructions {
    /// Example.
    ///
    ///   0. `[w]` Account that will be initialized as `Reward Manager`.
    ///   1. `[w]` The new account that to be initialized as the token account.
    ///   2. `[]`  Mint with wich the new token account will be associated on initialization.
    ///   3. `[]`  Manager account to be set as the `Reward Manager`.
    ///   4. `[]`  Reward Manager authority.
    ///   5. `[]`  Token program
    ///   6. `[]`  Rent sysvar
    InitRewardManager {
        /// Number of signer votes required for sending rewards
        min_votes: u8,
    },
}

/// Create `InitRewardManager` instruction
pub fn init(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    manager: &Pubkey,
    min_votes: u8,
) -> Result<Instruction, ProgramError> {
    let init_data = Instructions::InitRewardManager { min_votes };

    let (authority, _) = Pubkey::find_program_address(&[reward_manager.as_ref()], program_id);
    let data = init_data.try_to_vec()?;
    let accounts = vec![
        AccountMeta::new(*reward_manager, false),
        AccountMeta::new(*token_account, false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new_readonly(*manager, false),
        AccountMeta::new_readonly(authority, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

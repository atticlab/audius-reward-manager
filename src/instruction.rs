//! Instruction types

use std::array::IntoIter;

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program, sysvar,
};

use crate::utils::{get_address_pair, get_base_address};

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum Instructions {
    ///   Initialize `Reward Manager`
    ///
    ///   0. `[w]` Account that will be initialized as `Reward Manager`.
    ///   1. `[w]` The new account that to be initialized as the token account.
    ///   2. `[]`  Mint with wich the new token account will be associated on initialization.
    ///   3. `[]`  Manager account to be set as the `Reward Manager`.
    ///   4. `[]`  `Reward Manager` authority.
    ///   5. `[]`  Token program
    ///   6. `[]`  Rent sysvar
    InitRewardManager {
        /// Number of signer votes required for sending rewards
        min_votes: u8,
    },

    ///   Admin method creating new authorized sender
    ///
    ///   0. `[]`  `Reward Manager`
    ///   1. `[s]` Manager account
    ///   2. `[]`  `Reward Manager` authority
    ///   3. `[]`  Funder account
    ///   4. `[]`  Addidable sender
    ///   5. `[]`  System program id
    ///   6. `[]`  Rent sysvar
    CreateSender {
        /// Ethereum address
        eth_address: [u8; 20],
    },

    ///   Admin method removing sender
    ///  
    ///   0. `[]`   `Reward Manager`
    ///   1. `[s]`  Manager account
    ///   2. `[]`   `Reward Manager` authority
    ///   3. `[w]`  Removed sender
    ///   4. `[]`   Refunder account
    DeleteSender,

    ///
    ///
    /// 0. `[r]`  reward_manager
    /// 1. `[r]`  `Reward Manager` authority
    /// 2. `[ws]` funder
    /// 3. `[w]`  new_sender
    /// 4. `[r]`  old_sender_0
    /// ... Bunch of old senders which prove adding new one
    /// n. `[r]`  old_sender_n
    AddSender {
       /// Ethereum address
       eth_address: [u8; 20], 
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
    let data = init_data.try_to_vec()?;

    let (base, _) = get_base_address(reward_manager, program_id);

    let accounts = vec![
        AccountMeta::new(*reward_manager, false),
        AccountMeta::new(*token_account, false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new_readonly(*manager, false),
        AccountMeta::new_readonly(base, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `CreateSender` instruction
pub fn create_sender(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    manager_account: &Pubkey,
    funder_account: &Pubkey,
    eth_address: [u8; 20],
) -> Result<Instruction, ProgramError> {
    let create_data = Instructions::CreateSender { eth_address };
    let data = create_data.try_to_vec()?;

    let pair = get_address_pair(program_id, reward_manager, eth_address)?;

    let accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(*manager_account, true),
        AccountMeta::new_readonly(pair.base.address, false),
        AccountMeta::new(*funder_account, true),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `DeleteSender` instruction
pub fn delete_sender(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    manager_account: &Pubkey,
    refunder_account: &Pubkey,
    eth_address: [u8; 20],
) -> Result<Instruction, ProgramError> {
    let delete_data = Instructions::DeleteSender;
    let data = delete_data.try_to_vec()?;

    let pair = get_address_pair(program_id, reward_manager, eth_address)?;

    let accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(*manager_account, true),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new(*refunder_account, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

pub fn add_sender<I>(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    funder: &Pubkey,
    eth_address: [u8; 20],
    signers: I,
) -> Result<Instruction, ProgramError>
where
    I: IntoIterator<Item = Pubkey>
{
    let data = Instructions::AddSender { eth_address }.try_to_vec()?;

    let pair = get_address_pair(program_id, reward_manager, eth_address)?;

    let accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(pair.base.address, false),
        AccountMeta::new(*funder, false),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];
    let iter = signers.into_iter().map(|i| AccountMeta::new_readonly(i, true));
    accounts.extend(iter);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

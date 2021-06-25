//! Instruction types

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program, sysvar,
};

use crate::{
    processor::{SENDER_SEED_PREFIX, TRANSFER_SEED_PREFIX},
    utils::{get_address_pair, get_base_address},
};
/// `Transfer` instruction parameters
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct Transfer {
    /// Amount to transfer
    pub amount: u64,
    /// ID generated on backend
    pub id: String,
    /// Recipient's Eth address
    pub eth_recipient: [u8; 20],
}

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum Instructions {
    ///   Initialize `Reward Manager`
    ///
    ///   0. `[w]` Account that will be initialized as `Reward Manager`.
    ///   1. `[w]` The new account that to be initialized as the token account.
    ///   2. `[]`  Mint with which the new token account will be associated on initialization.
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
    ///   0. `[]` `Reward Manager`
    ///   1. `[s]` Manager account
    ///   2. `[]`  `Reward Manager` authority
    ///   3. `[w]`  Removed sender
    ///   4. `[]`  Refunder account
    DeleteSender,

    ///   Transfer tokens to pointed receiver
    ///
    ///   0. `[]` `Reward Manager`
    ///   1. `[]` `Reward Manager` authority. Program account
    ///   2. `[w]` Vault with all the "reward" tokens. Program is authority
    ///   3. `[]` Bot oracle
    ///   4. `[w]` Recipient. Key generated from Eth address
    ///   5. `[sw]` Funder. Account which pay for new account creation
    ///   6. `[w]` Transfer account to create
    ///   6. `[r]` Sysvar instruction id
    ///   7. `[]` Senders
    ///   ...
    ///   n. `[]`
    Transfer {
        /// Amount to transfer
        amount: u64,
        /// ID generated on backend
        id: String,
        /// Recipient's Eth address
        eth_recipient: [u8; 20],
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

    let (base, _) = get_base_address(program_id, reward_manager);

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

    let mut seed = Vec::new();
    seed.extend_from_slice(&eth_address.as_ref());
    seed.extend_from_slice(SENDER_SEED_PREFIX.as_ref());
    let pair = get_address_pair(program_id, reward_manager, seed.as_ref())?;

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

    let mut seed = Vec::new();
    seed.extend_from_slice(&eth_address.as_ref());
    seed.extend_from_slice(SENDER_SEED_PREFIX.as_ref());
    let pair = get_address_pair(program_id, reward_manager, seed.as_ref())?;

    let accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(*manager_account, true),
        AccountMeta::new_readonly(pair.base.address, false),
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

/// Create `Transfer` instruction
#[allow(clippy::too_many_arguments)]
pub fn transfer(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    recipient: &Pubkey,
    vault_token_account: &Pubkey,
    bot_oracle: &Pubkey,
    funder: &Pubkey,
    senders: Vec<Pubkey>,
    params: Transfer,
) -> Result<Instruction, ProgramError> {
    let data = Instructions::Transfer {
        amount: params.amount,
        id: params.id.clone(),
        eth_recipient: params.eth_recipient,
    }
    .try_to_vec()?;

    let mut seed = Vec::new();
    seed.extend_from_slice(TRANSFER_SEED_PREFIX.as_ref());
    seed.extend_from_slice(params.id.as_ref());
    let transfer_acc_to_create = get_address_pair(program_id, reward_manager, seed.as_ref())?;

    let mut accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(transfer_acc_to_create.base.address, false),
        AccountMeta::new(*recipient, false),
        AccountMeta::new(*vault_token_account, false),
        AccountMeta::new_readonly(*bot_oracle, false),
        AccountMeta::new(*funder, true),
        AccountMeta::new(transfer_acc_to_create.derive.address, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    for acc in senders {
        accounts.push(AccountMeta::new_readonly(acc, false))
    }

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

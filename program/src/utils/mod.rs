#![allow(missing_docs)]
use crate::{
    error::AudiusProgramError,
    state::{VerifiedMessage, TOTAL_VERIFIED_MESSAGES},
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::IsInitialized,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
};
use std::collections::BTreeSet;

mod signs;
pub use signs::*;

/// Assert owned by
pub fn assert_owned_by(account: &AccountInfo, owner: &Pubkey) -> ProgramResult {
    if account.owner != owner {
        Err(AudiusProgramError::IncorrectOwner.into())
    } else {
        Ok(())
    }
}

/// Assert unitialized
pub fn assert_uninitialized<T: IsInitialized>(account: &T) -> ProgramResult {
    if account.is_initialized() {
        Err(ProgramError::AccountAlreadyInitialized)
    } else {
        Ok(())
    }
}

/// Assert account key
pub fn assert_account_key(account_info: &AccountInfo, key: &Pubkey) -> ProgramResult {
    if *account_info.key != *key {
        Err(ProgramError::InvalidArgument)
    } else {
        Ok(())
    }
}

/// Assert unique senders & operators
pub fn assert_unique_senders(messages: &[VerifiedMessage]) -> ProgramResult {
    let mut uniq_senders = BTreeSet::new();
    let mut uniq_operators = BTreeSet::new();
    let mut messages_iter = messages.iter();

    if messages.len() > TOTAL_VERIFIED_MESSAGES {
        return Err(AudiusProgramError::MessagesOverflow.into());
    }

    // Check sender collision
    if !messages_iter.all(move |x| uniq_senders.insert(x.address)) {
        return Err(AudiusProgramError::RepeatedSenders.into());
    }

    // Check operator collision
    if !messages_iter.all(move |x| uniq_operators.insert(x.operator)) {
        return Err(AudiusProgramError::OperatorCollision.into());
    }

    Ok(())
}

/// Assert messages
pub fn assert_messages(
    valid_message: &[u8],
    valid_bot_oracle_message: &[u8],
    bot_oracle_address: &EthereumAddress,
    messages: &[VerifiedMessage],
) -> ProgramResult {
    for VerifiedMessage {
        message, address, ..
    } in messages
    {
        if address == bot_oracle_address {
            if valid_bot_oracle_message != &message[..valid_bot_oracle_message.len()] {
                return Err(AudiusProgramError::IncorrectMessages.into());
            }
        } else if valid_message != &message[..valid_message.len()] {
            return Err(AudiusProgramError::IncorrectMessages.into());
        }
    }

    Ok(())
}

pub fn assert_initialized<T: IsInitialized>(account: &T) -> ProgramResult {
    if !account.is_initialized() {
        Err(ProgramError::InvalidAccountData)
    } else {
        Ok(())
    }
}

/// Represent compressed ethereum pubkey
pub type EthereumAddress = [u8; 20];

/// Generates seed bump for authorities
pub fn find_program_address(program_id: &Pubkey, pubkey: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[&pubkey.to_bytes()[..32]], program_id)
}

/// Generates derived address
pub fn find_derived_address(program_id: &Pubkey, base: &Pubkey, seed: &[u8]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[&base.to_bytes()[..32], seed], program_id)
}

pub fn find_derived_pair(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    seed: &[u8],
) -> (Pubkey, Pubkey, u8) {
    let (reward_manager_authority, _) = find_program_address(program_id, reward_manager);
    let (derived_address, bump_seed) =
        find_derived_address(program_id, &reward_manager_authority, seed);

    (reward_manager_authority, derived_address, bump_seed)
}

/// Initialize SPL accont instruction.
pub fn spl_initialize_account<'a>(
    account: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    authority: AccountInfo<'a>,
    rent: AccountInfo<'a>,
) -> ProgramResult {
    let ix = spl_token::instruction::initialize_account(
        &spl_token::id(),
        account.key,
        mint.key,
        authority.key,
    )?;

    invoke(&ix, &[account, mint, authority, rent])
}

/// Transfer tokens with program address
#[allow(clippy::too_many_arguments)]
pub fn spl_token_transfer<'a>(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    source: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
) -> ProgramResult {
    let bump_seed = find_program_address(program_id, reward_manager).1;

    let authority_signature_seeds = [&reward_manager.to_bytes()[..32], &[bump_seed]];
    let signers = &[&authority_signature_seeds[..]];

    let tx = spl_token::instruction::transfer(
        &spl_token::id(),
        source.key,
        destination.key,
        authority.key,
        &[],
        amount,
    )?;
    invoke_signed(
        &tx,
        &[source.clone(), destination.clone(), authority.clone()],
        signers,
    )
}

/// Create account
#[allow(clippy::too_many_arguments)]
pub fn create_account<'a>(
    program_id: &Pubkey,
    from: AccountInfo<'a>,
    to: AccountInfo<'a>,
    space: usize,
    signers_seeds: &[&[&[u8]]],
    rent: &Rent,
) -> ProgramResult {
    let ix = system_instruction::create_account(
        from.key,
        to.key,
        rent.minimum_balance(space),
        space as u64,
        program_id,
    );

    invoke_signed(&ix, &[from, to], signers_seeds)
}

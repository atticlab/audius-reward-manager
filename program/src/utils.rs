#![allow(missing_docs)]

use crate::{
    error::{to_audius_program_error, AudiusProgramError},
    instruction::TransferArgs,
    processor::SENDER_SEED_PREFIX,
    state::{SenderAccount, VerifiedMessage},
};
use borsh::BorshDeserialize;
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::Instruction,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::IsInitialized,
    pubkey::{Pubkey, PubkeyError},
    rent::Rent,
    secp256k1_program, system_instruction, sysvar,
};
use std::collections::{BTreeSet, HashSet};
use std::{collections::BTreeMap, convert::TryInto};

/// Represent compressed ethereum pubkey
pub type EthereumAddress = [u8; 20];

/// Base PDA related with some mint
pub struct Base {
    pub address: Pubkey,
    pub seed: u8,
}

/// Derived account related with some Base and Ethereum address
pub struct Derived {
    pub address: Pubkey,
    pub seed: String,
}

/// Base with related
pub struct AddressPair {
    pub base: Base,
    pub derive: Derived,
}

/// Macro to check if program is owner for pointed accounts
#[macro_export]
macro_rules! is_owner {
    (
        $program_id:expr,
        $($account:expr),+
    )
    => {
        {
            $(
                if *$account.owner != $program_id {
                    return Err(ProgramError::IncorrectProgramId);
                }
            )+


            std::result::Result::<(),ProgramError>::Ok(())
        }
    }
}

/// Return `Base` account with seed and corresponding derive
/// with seed
pub fn get_address_pair(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    seed: Vec<u8>,
) -> Result<AddressPair, PubkeyError> {
    let (base_pk, base_seed) = get_base_address(program_id, reward_manager);
    let (derived_pk, derive_seed) =
        get_derived_address(program_id, &base_pk.clone(), seed.as_ref())?;
    Ok(AddressPair {
        base: Base {
            address: base_pk,
            seed: base_seed,
        },
        derive: Derived {
            address: derived_pk,
            seed: derive_seed,
        },
    })
}

/// Return PDA(that named `Base`) corresponding to specific `reward manager`
/// and it bump seed
pub fn get_base_address(program_id: &Pubkey, reward_manager: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[&reward_manager.to_bytes()[..32]], program_id)
}

/// Return derived token account address corresponding to specific
/// ethereum account and it seed
pub fn get_derived_address(
    program_id: &Pubkey,
    base: &Pubkey,
    seeds: &[u8],
) -> Result<(Pubkey, String), PubkeyError> {
    let eseed = bs58::encode(seeds).into_string();
    Pubkey::create_with_seed(&base, eseed.as_str(), program_id).map(|i| (i, eseed))
}

/// Transfer tokens with program address
#[allow(clippy::too_many_arguments)]
pub fn token_transfer<'a>(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    source: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
) -> ProgramResult {
    let bump_seed = get_base_address(program_id, reward_manager).1;

    let authority_signature_seeds = [&reward_manager.to_bytes()[..32], &[bump_seed]];
    let signers = &[&authority_signature_seeds[..]];

    let tx = spl_token::instruction::transfer(
        &spl_token::id(),
        source.key,
        destination.key,
        authority.key,
        &[&authority.key],
        amount,
    )?;
    invoke_signed(
        &tx,
        &[source.clone(), destination.clone(), authority.clone()],
        signers,
    )
}

/// Create account with seed signed
#[allow(clippy::too_many_arguments)]
pub fn create_account_with_seed<'a>(
    program_id: &Pubkey,
    funder: &AccountInfo<'a>,
    account_to_create: &AccountInfo<'a>,
    base: &AccountInfo<'a>,
    reward_manager: &Pubkey,
    seeds: Vec<u8>,
    required_lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> ProgramResult {
    let bump_seed = get_base_address(program_id, reward_manager).1;

    let signature = &[&reward_manager.to_bytes()[..32], &[bump_seed]];
    invoke_signed(
        &system_instruction::create_account_with_seed(
            &funder.key,
            &account_to_create.key,
            &base.key,
            &bs58::encode(seeds).into_string(),
            required_lamports,
            space,
            owner,
        ),
        &[funder.clone(), account_to_create.clone(), base.clone()],
        &[signature],
    )
}

pub fn get_secp_instructions(
    index_current_instruction: u16,
    necessary_instructions_count: usize,
    instruction_info: &AccountInfo,
) -> Result<Vec<Instruction>, AudiusProgramError> {
    let mut secp_instructions: Vec<Instruction> = Vec::new();

    for ind in 0..index_current_instruction {
        let instruction = sysvar::instructions::load_instruction_at(
            ind as usize,
            &instruction_info.data.borrow(),
        )
        .map_err(to_audius_program_error)?;

        if instruction.program_id == secp256k1_program::id() {
            secp_instructions.push(instruction);
        }
    }

    if secp_instructions.len() != necessary_instructions_count {
        return Err(AudiusProgramError::Secp256InstructionMissing);
    }

    Ok(secp_instructions)
}

pub fn get_eth_addresses<'a>(
    program_id: &Pubkey,
    reward_manager_key: &Pubkey,
    signers: Vec<&AccountInfo<'a>>,
) -> Result<(Vec<EthereumAddress>, BTreeSet<EthereumAddress>), ProgramError> {
    let mut senders_eth_addresses: Vec<EthereumAddress> = Vec::new();
    let mut operators = BTreeSet::<EthereumAddress>::new();

    for signer in signers {
        let signer_data = SenderAccount::try_from_slice(&signer.data.borrow())?;
        if !signer_data.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        is_owner!(*program_id, signer)?;

        let generated_sender_key = get_address_pair(
            program_id,
            reward_manager_key,
            [
                SENDER_SEED_PREFIX.as_ref(),
                signer_data.eth_address.as_ref(),
            ]
            .concat(),
        )?;
        if generated_sender_key.derive.address != *signer.key {
            return Err(ProgramError::InvalidSeeds);
        }
        if senders_eth_addresses.contains(&signer_data.eth_address) {
            return Err(AudiusProgramError::RepeatedSenders.into());
        }
        if !operators.insert(signer_data.operator) {
            return Err(AudiusProgramError::OperatorCollision.into());
        }
        senders_eth_addresses.push(signer_data.eth_address);
    }

    Ok((senders_eth_addresses, operators))
}

pub fn get_signer_from_secp_instruction(secp_instruction_data: Vec<u8>) -> EthereumAddress {
    let eth_address_offset = 12;
    let instruction_signer =
        secp_instruction_data[eth_address_offset..eth_address_offset + 20].to_vec();
    let instruction_signer: EthereumAddress = instruction_signer.as_slice().try_into().unwrap();
    instruction_signer
}

pub fn validate_eth_signature(
    expected_message: &[u8],
    secp_instruction_data: Vec<u8>,
) -> Result<(), ProgramError> {
    //NOTE: meta (12) + address (20) + signature (65) = 97
    let message_data_offset = 97;
    let instruction_message = secp_instruction_data[message_data_offset..].to_vec();
    if instruction_message != *expected_message {
        return Err(AudiusProgramError::SignatureVerificationFailed.into());
    }

    Ok(())
}

pub trait VerifierFn =
    FnOnce(Vec<Instruction>, Vec<EthereumAddress>, BTreeSet<EthereumAddress>) -> ProgramResult;

fn vec_into_checkmap(vec: &Vec<EthereumAddress>) -> BTreeMap<EthereumAddress, bool> {
    let mut map = BTreeMap::new();
    for item in vec {
        map.insert(*item, false);
    }
    map
}

fn check_signer(
    checkmap: &mut BTreeMap<EthereumAddress, bool>,
    eth_signer: &EthereumAddress,
) -> ProgramResult {
    if let Some(val) = checkmap.get_mut(eth_signer) {
        if !*val {
            *val = true;
        } else {
            return Err(AudiusProgramError::SignCollission.into());
        }
    } else {
        return Err(AudiusProgramError::WrongSigner.into());
    }
    Ok(())
}

pub fn build_verify_secp_transfer(
    bot_oracle: SenderAccount,
    transfer_data: TransferArgs,
) -> impl VerifierFn {
    return Box::new(
        move |instructions: Vec<Instruction>,
              signers: Vec<EthereumAddress>,
              mut operators: BTreeSet<EthereumAddress>| {
            let mut successful_verifications = 0;
            let mut checkmap = vec_into_checkmap(&signers);

            let bot_oracle_message = [
                transfer_data.eth_recipient.as_ref(),
                b"_",
                transfer_data.amount.to_le_bytes().as_ref(),
                b"_",
                transfer_data.id.as_ref(),
            ]
            .concat();

            let senders_message = [
                transfer_data.eth_recipient.as_ref(),
                b"_",
                transfer_data.amount.to_le_bytes().as_ref(),
                b"_",
                transfer_data.id.as_ref(),
                b"_",
                bot_oracle.eth_address.as_ref(),
            ]
            .concat();

            for instruction in instructions {
                let eth_signer = get_signer_from_secp_instruction(instruction.data.clone());
                if eth_signer == bot_oracle.eth_address {
                    validate_eth_signature(bot_oracle_message.as_ref(), instruction.data.clone())?;
                    if !operators.insert(bot_oracle.operator) {
                        return Err(AudiusProgramError::OperatorCollision.into());
                    }
                    successful_verifications += 1;
                }
                if signers.contains(&eth_signer) {
                    check_signer(&mut checkmap, &eth_signer)?;
                    validate_eth_signature(senders_message.as_ref(), instruction.data)?;
                    successful_verifications += 1;
                }
            }

            // NOTE: +1 it's bot oracle
            if successful_verifications != signers.len() + 1 {
                return Err(AudiusProgramError::SignatureVerificationFailed.into());
            }

            Ok(())
        },
    );
}

pub fn build_verify_secp_add_sender(
    reward_manager_key: Pubkey,
    new_sender: EthereumAddress,
) -> impl VerifierFn {
    return Box::new(
        move |instructions: Vec<Instruction>,
              signers: Vec<EthereumAddress>,
              _operators: BTreeSet<EthereumAddress>| {
            let mut checkmap = vec_into_checkmap(&signers);

            let expected_message = [reward_manager_key.as_ref(), new_sender.as_ref()].concat();
            for instruction in instructions {
                let eth_signer = get_signer_from_secp_instruction(instruction.data.clone());
                check_signer(&mut checkmap, &eth_signer)?;
                validate_eth_signature(expected_message.as_ref(), instruction.data)?;
            }

            Ok(())
        },
    );
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

/// Checks that the user signed message with his ethereum private key
pub fn check_ethereum_sign(
    instruction_info: &AccountInfo,
    expected_signer: &EthereumAddress,
    expected_message: &[u8],
) -> ProgramResult {
    let index = sysvar::instructions::load_current_index(&instruction_info.data.borrow());

    // Instruction can't be first in transaction
    // because must follow after `new_secp256k1_instruction`
    if index == 0 {
        return Err(AudiusProgramError::Secp256InstructionMissing.into());
    }

    // Load previous instruction
    let instruction = sysvar::instructions::load_instruction_at(
        (index - 1) as usize,
        &instruction_info.data.borrow(),
    )
    .map_err(to_audius_program_error)?;

    // Check that instruction is `new_secp256k1_instruction`
    if instruction.program_id != secp256k1_program::id() {
        return Err(AudiusProgramError::Secp256InstructionMissing.into());
    }

    let eth_signer = get_signer_from_secp_instruction(instruction.data.clone());

    if eth_signer != *expected_signer {
        return Err(AudiusProgramError::WrongSigner.into());
    }

    validate_eth_signature(expected_message, instruction.data)?;

    Ok(())
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
pub fn assert_unique_senders(messages: Vec<VerifiedMessage>) -> ProgramResult {
    let mut uniq_senders = HashSet::new();
    let mut uniq_operators = HashSet::new();
    let mut messages_iter = messages.into_iter();

    // Check sender collision
    if !messages_iter.all(move |x| uniq_senders.insert(x.0.address)) {
        return Err(AudiusProgramError::RepeatedSenders.into());
    }

    // Check operator collision
    if !messages_iter.all(move |x| uniq_operators.insert(x.1)) {
        return Err(AudiusProgramError::OperatorCollision.into());
    }

    Ok(())
}

/// Assert messages
pub fn assert_messages(valid_message: &[u8], messages: &Vec<VerifiedMessage>) -> ProgramResult {
    for (message, _) in messages {
        if valid_message != message.message {
            return Err(AudiusProgramError::IncorrectMessages.into());
        }
    }

    Ok(())
}

pub fn assert_initialized<A>(account: &A) -> ProgramResult
where
    A: IsInitialized,
{
    if !account.is_initialized() {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

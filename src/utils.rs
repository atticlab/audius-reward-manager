#![allow(missing_docs)]

use solana_program::pubkey::{Pubkey, PubkeyError};

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

/// Return `Base` account with seed and corresponding derive
/// with seed
pub fn get_address_pair(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    eth_address: EthereumAddress,
) -> Result<AddressPair, PubkeyError> {
    let (base_pk, base_seed) = get_base_address(program_id, reward_manager);
    let (derived_pk, derive_seed) = get_derived_address(program_id, &base_pk.clone(), eth_address)?;
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
    eth_address: EthereumAddress,
) -> Result<(Pubkey, String), PubkeyError> {
    let mut seed = Vec::new();
    seed.extend_from_slice(b"S_");
    seed.extend_from_slice(&eth_address.as_ref());
    let eseed = bs58::encode(seed).into_string();
    Pubkey::create_with_seed(&base, eseed.as_str(), program_id).map(|i| (i, eseed))
}
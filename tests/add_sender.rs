#![cfg(feature = "test-bpf")]
mod utils;
use std::mem::MaybeUninit;

use audius_reward_manager::{
    instruction,
    processor::SENDER_SEED_PREFIX,
    state::SenderAccount,
    utils::{get_address_pair, EthereumAddress},
};
use rand::{thread_rng, Rng};
use secp256k1::{PublicKey, SecretKey};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_program_test::*;
use solana_sdk::{
    secp256k1_instruction::{construct_eth_pubkey},
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use utils::{create_sender, program_test, new_secp256k1_instruction_2_0};

#[tokio::test]
async fn success() {
    let program_test = program_test();
    let mut rng = thread_rng();

    let reward_manager = Pubkey::new_unique();
    let manager_account = Keypair::new();
    let funder = Pubkey::new_unique();
    let eth_address: EthereumAddress = rng.gen();
    let operator: EthereumAddress = rng.gen();
    let keys: [[u8; 32]; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager,
            [SENDER_SEED_PREFIX.as_ref(), item.1.as_ref()].concat(),
        ).unwrap();

        signers[item.0] = pair.derive.address;
    }

    let pair = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager,
        [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
    )
    .unwrap();

    let mut context = program_test.start_with_context().await;
    let mut instructions = Vec::<Instruction>::new();

    // Create senders 
    for key in &keys {
        let sender_priv_key = SecretKey::parse(&key).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        let operator: EthereumAddress = rng.gen(); 
        create_sender(
            &mut context,
            &reward_manager,
            &manager_account,
            eth_address,
            operator,
        )
        .await;
    }

    // Insert signs instructions
    let message = [reward_manager.as_ref(), pair.derive.address.as_ref()].concat();
    for item in keys.iter().enumerate() {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::add_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &funder,
            eth_address,
            operator,
            &signers,
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context.banks_client.process_transaction(tx).await.unwrap();

    assert_eq!(
        SenderAccount::new(reward_manager, eth_address, operator),
        context
            .banks_client
            .get_account_data_with_borsh(pair.derive.address)
            .await
            .unwrap()
    );
}

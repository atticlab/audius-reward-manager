#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::instruction;
use solana_program::pubkey::Pubkey;
use solana_program_test::*;
use solana_sdk::{signer::Signer, transaction::Transaction};
use utils::program_test;

#[tokio::test]
async fn success() {
    let program_test = program_test();

    let reward_manager = Pubkey::new_unique();
    let funder = Pubkey::new_unique();
    let eth_address = [0u8; 20];
    let operator = [0u8; 20];
    let signers = [
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];

    let mut context = program_test.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[instruction::add_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &funder,
            eth_address,
            operator,
            &signers,
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context.banks_client.process_transaction(tx).await.unwrap();
}

#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::instruction;
use solana_program::pubkey::Pubkey;
use solana_program_test::*;
use solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction};
use utils::program_test;

#[tokio::test]
async fn success() {
    let program_test = program_test();

    let reward_manager = Pubkey::new_unique();
    let manager_account = Keypair::new();
    let sender = Pubkey::new_unique();
    let refunder_account = Pubkey::new_unique();

    let mut context = program_test.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[instruction::delete_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &manager_account.pubkey(),
            &sender,
            &refunder_account,
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer, &manager_account],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();

    let account = context.banks_client.get_account(sender).await.unwrap();
    assert!(account.is_none());
}

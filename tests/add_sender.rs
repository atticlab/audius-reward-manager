#![cfg(feature = "test-bpf")]
mod utils;

#[tokio::test]
async fn success() {
    let mut program_test = program_test();
    let mut context = program_test.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[instruction::create_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &manager_account.pubkey(),
            &context.payer.pubkey(),
            eth_address,
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer, &manager_account],
        context.last_blockhash,
    );
    context.banks_client.process_transaction(tx).await.unwrap();
}

#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::{instruction, processor::SENDER_SEED_PREFIX, state::SenderAccount, utils::{EthereumAddress, get_address_pair}};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_program_test::*;
use solana_sdk::{secp256k1_instruction::{construct_eth_pubkey, new_secp256k1_instruction}, signature::Keypair, signer::Signer, transaction::Transaction};
use secp256k1::SecretKey;
use utils::program_test;
use rand::{thread_rng, Rng};

// #[tokio::test]
// async fn success() {
//     let program_test = program_test();
//     let mut rng = thread_rng();

//     let reward_manager = Pubkey::new_unique();
//     let funder = Pubkey::new_unique();
//     let eth_address: EthereumAddress = rng.gen();
//     let operator: EthereumAddress = rng.gen();
//     let keys: [EthereumAddress; 3] = rng.gen();
//     let signers = [
//         Pubkey::new_unique(),
//         Pubkey::new_unique(),
//         Pubkey::new_unique(),
//     ];

//     let pair = get_address_pair(
//         &audius_reward_manager::id(),
//         &reward_manager,
//         [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
//     ).unwrap();

//     let mut context = program_test.start_with_context().await;
//     let mut instructions = Vec::<Instruction>::new();

//     for key in &keys {
//         let priv_key = SecretKey::parse(key).unwrap();
//         let message = [reward_manager.as_ref(), pair.derive.address.as_ref()].concat();
//         let inst = new_secp256k1_instruction(&priv_key, message.as_ref());
//         instructions.push(inst)
//     }

//     instructions.push(
//         instruction::add_sender(
//             &audius_reward_manager::id(),
//             &reward_manager,
//             &funder,
//             eth_address,
//             operator,
//             &signers,
//         ).unwrap()
//     );

//     let tx = Transaction::new_signed_with_payer(
//         &instructions,
//         Some(&context.payer.pubkey()),
//         &[&context.payer],
//         context.last_blockhash,
//     );
//     context.banks_client.process_transaction(tx).await.unwrap();
    
//     assert_eq!(
//         SenderAccount::new(reward_manager, eth_address, operator),
//         context
//             .banks_client
//             .get_account_data_with_borsh(pair.derive.address)
//             .await
//             .unwrap()
//     );
// }

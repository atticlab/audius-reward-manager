#![cfg(feature = "test-bpf")]
mod assert;
mod utils;

use audius_reward_manager::{
    error::AudiusProgramError,
    instruction,
    processor::{SENDER_SEED_PREFIX, TRANSFER_ACC_SPACE, TRANSFER_SEED_PREFIX},
    state::{SignedPayload, VerifiedMessages},
    utils::{get_address_pair, EthereumAddress},
};
use rand::{thread_rng, Rng};
use secp256k1::{PublicKey, SecretKey};
use solana_program::{
    instruction::Instruction, program_pack::Pack, pubkey::Pubkey, system_instruction,
};
use solana_program_test::*;
use solana_sdk::{
    instruction::InstructionError,
    secp256k1_instruction::*,
    signature::Keypair,
    signer::Signer,
    transaction::{Transaction, TransactionError},
    transport::TransportError,
};
use std::convert::TryInto;
use std::mem::MaybeUninit;
use utils::*;

#[tokio::test]
async fn success() {
    let mut program_test = program_test();
    let mut rng = thread_rng();

    let mut context = program_test.start_with_context().await;

    let mint = Keypair::new();
    let mint_authority = Keypair::new();

    let token_account = Keypair::new();
    let reward_manager = Keypair::new();
    let manager_account = Keypair::new();

    let rent = context.banks_client.get_rent().await.unwrap();

    create_mint(
        &mut context,
        &mint,
        rent.minimum_balance(spl_token::state::Mint::LEN),
        &mint_authority.pubkey(),
    )
    .await
    .unwrap();

    init_reward_manager(
        &mut context,
        &reward_manager,
        &token_account,
        &mint.pubkey(),
        &manager_account.pubkey(),
        3,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let tokens_amount = 10_000u64;
    let recipient_eth_key = [7u8; 20];
    let transfer_id = "4r4t23df32543f55";

    let senders_message_vec = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();
    let mut senders_message: [u8; 128] = [0; 128];
    senders_message[..senders_message_vec.len()].copy_from_slice(&senders_message_vec);

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    let mut signed_payloads: Vec<SignedPayload> = vec![];
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;

        signed_payloads.push(SignedPayload {
            address: eth_address,
            message: senders_message,
        })
    }

    mint_tokens_to(
        &mut context,
        &mint.pubkey(),
        &token_account.pubkey(),
        &mint_authority,
        tokens_amount,
    )
    .await
    .unwrap();

    let mut instructions = Vec::<Instruction>::new();

    let priv_key = SecretKey::parse(&keys[0]).unwrap();
    let sender_sign = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), 0);
    instructions.push(sender_sign);

    let verified_messages = Keypair::new();

    instructions.push(system_instruction::create_account(
        &context.payer.pubkey(),
        &verified_messages.pubkey(),
        rent.minimum_balance(VerifiedMessages::LEN),
        VerifiedMessages::LEN as u64,
        &audius_reward_manager::id(),
    ));

    println!("LEN {}", std::mem::size_of::<VerifiedMessages>());

    instructions.push(
        instruction::verify_transfer_signature(
            &audius_reward_manager::id(),
            &verified_messages.pubkey(),
            &reward_manager.pubkey(),
            &signers[0],
            &context.payer.pubkey(),
            signed_payloads[0].clone(),
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer, &verified_messages],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();
}

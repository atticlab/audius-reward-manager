mod utils;
use claimable_tokens::utils::program::get_address_pair;
use clap::{
    crate_description, crate_name, crate_version, value_t, value_t_or_exit, App, AppSettings, Arg,
    SubCommand,
};

use audius_reward_manager::{
    instruction::{
        add_sender, create_sender, delete_sender, init, transfer, verify_transfer_signature,
    },
    processor::SENDER_SEED_PREFIX,
    state::{RewardManager, SenderAccount, VerifiedMessages},
    utils::find_derived_pair
};

use hex::FromHex;
use solana_clap_utils::{
    input_parsers::{keypair_of, pubkey_of},
    input_validators::{is_keypair, is_keypair_or_ask_keyword, is_parsable, is_pubkey, is_url},
    keypair::signer_from_path,
};
use solana_client::rpc_client::RpcClient;
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    program_pack::Pack,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_token::state::Account;
use spl_token::ui_amount_to_amount;
use std::process::exit;
use std::str::FromStr;
use utils::Transaction as CustomTransaction;
use utils::{
    is_csv_file, is_eth_address, is_hex, new_secp256k1_instruction_2_0, sign_message, SenderData,
};

#[allow(dead_code)]
pub struct Config {
    rpc_client: RpcClient,
    verbose: bool,
    owner: Box<dyn Signer>,
    fee_payer: Box<dyn Signer>,
    commitment_config: CommitmentConfig,
}

type Error = Box<dyn std::error::Error>;
type CommandResult = Result<Option<Transaction>, Error>;

const HEX_ETH_ADDRESS_DECODING_ERROR: &str = "Ethereum address decoding failed";
const HEX_ETH_SECRET_DECODING_ERROR: &str = "Ethereum secret decoding failed";

fn command_init(
    config: &Config,
    reward_manager_keypair: Option<Keypair>,
    token_mint: Pubkey,
    min_votes: u8,
) -> CommandResult {
    let mut instructions: Vec<Instruction> = Vec::new();

    let reward_manager_keypair = reward_manager_keypair.unwrap_or_else(Keypair::new);
    println!(
        "Reward manager key created: {:?}",
        reward_manager_keypair.pubkey()
    );

    let reward_manager_balance = config
        .rpc_client
        .get_minimum_balance_for_rent_exemption(RewardManager::LEN)?;

    instructions.push(system_instruction::create_account(
        &config.fee_payer.pubkey(),
        &reward_manager_keypair.pubkey(),
        reward_manager_balance,
        RewardManager::LEN as u64,
        &audius_reward_manager::id(),
    ));

    let reward_manager_token_acc = Keypair::new();
    println!(
        "Reward manager token key created: {:?}",
        reward_manager_token_acc.pubkey()
    );

    let token_acc_balance = config
        .rpc_client
        .get_minimum_balance_for_rent_exemption(Account::LEN)?;

    instructions.push(system_instruction::create_account(
        &config.fee_payer.pubkey(),
        &reward_manager_token_acc.pubkey(),
        token_acc_balance,
        Account::LEN as u64,
        &spl_token::id(),
    ));

    instructions.push(init(
        &audius_reward_manager::id(),
        &reward_manager_keypair.pubkey(),
        &reward_manager_token_acc.pubkey(),
        &token_mint,
        &config.owner.pubkey(),
        min_votes,
    )?);

    let transaction = CustomTransaction {
        instructions,
        signers: vec![
            config.fee_payer.as_ref(),
            config.owner.as_ref(),
            &reward_manager_keypair,
            &reward_manager_token_acc,
        ],
    };

    transaction.sign(config, reward_manager_balance + token_acc_balance)
}

fn command_create_sender(
    config: &Config,
    reward_manager: Pubkey,
    sender_eth_address: String,
    operator_eth_address: String,
) -> CommandResult {
    let decoded_eth_sender_address =
        <[u8; 20]>::from_hex(sender_eth_address).expect(HEX_ETH_ADDRESS_DECODING_ERROR);

    let decoded_eth_operator_address =
        <[u8; 20]>::from_hex(operator_eth_address).expect(HEX_ETH_ADDRESS_DECODING_ERROR);

    let (_, derived_address, _) = find_derived_pair(
        &audius_reward_manager::id(),
        &reward_manager,
        [
            SENDER_SEED_PREFIX.as_ref(),
            decoded_eth_sender_address.as_ref(),
        ]
        .concat()
        .as_ref(),
    );

    println!("New sender account created: {:?}", derived_address);

    let transaction = CustomTransaction {
        instructions: vec![create_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &config.owner.pubkey(),
            &config.fee_payer.pubkey(),
            decoded_eth_sender_address,
            decoded_eth_operator_address,
        )?],
        signers: vec![config.fee_payer.as_ref(), config.owner.as_ref()],
    };

    transaction.sign(config, 0)
}

fn command_delete_sender(
    config: &Config,
    reward_manager: Pubkey,
    eth_sender_address: String,
) -> CommandResult {
    let decoded_eth_sender_address =
        <[u8; 20]>::from_hex(eth_sender_address).expect(HEX_ETH_ADDRESS_DECODING_ERROR);

    let transaction = CustomTransaction {
        instructions: vec![delete_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &config.owner.pubkey(),
            &config.fee_payer.pubkey(),
            decoded_eth_sender_address,
        )?],
        signers: vec![config.fee_payer.as_ref(), config.owner.as_ref()],
    };

    transaction.sign(config, 0)
}

fn command_add_sender(
    config: &Config,
    reward_manager: Pubkey,
    new_sender: String,
    operator_address: String,
    senders_secrets: String,
) -> CommandResult {
    let mut instructions = Vec::new();

    let mut senders = Vec::new();
    let mut secrets = Vec::new();
    let mut rdr = csv::Reader::from_path(&senders_secrets)?;

    let new_sender = <[u8; 20]>::from_hex(new_sender).expect(HEX_ETH_ADDRESS_DECODING_ERROR);
    let message_to_sign = [reward_manager.as_ref(), new_sender.as_ref()].concat();
    let operator_address =
        <[u8; 20]>::from_hex(operator_address).expect(HEX_ETH_ADDRESS_DECODING_ERROR);

    println!("Signing message with senders private keys...");

    for key in rdr.deserialize() {
        let deserialized_sender_data: SenderData = key?;
        let decoded_secret = <[u8; 32]>::from_hex(deserialized_sender_data.eth_secret)
            .expect(HEX_ETH_SECRET_DECODING_ERROR);

        senders.push(Pubkey::from_str(&deserialized_sender_data.solana_key)?);
        secrets.push(secp256k1::SecretKey::parse(&decoded_secret)?);
    }

    instructions.append(&mut sign_message(message_to_sign.as_ref(), secrets));

    instructions.push(add_sender(
        &audius_reward_manager::id(),
        &reward_manager,
        &config.fee_payer.pubkey(),
        new_sender,
        operator_address,
        &senders,
    )?);

    let (_, derived_address, _) = find_derived_pair(
        &audius_reward_manager::id(),
        &reward_manager,
        [SENDER_SEED_PREFIX.as_ref(), new_sender.as_ref()]
            .concat()
            .as_ref(),
    );

    println!("New sender account was created: {:?}", derived_address);

    let transaction = CustomTransaction {
        instructions,
        signers: vec![config.fee_payer.as_ref(), config.owner.as_ref()],
    };

    transaction.sign(config, 0)
}

#[allow(clippy::too_many_arguments)]
fn command_verify_transfer_signature(
    config: &Config,
    reward_manager_pubkey: Pubkey,
    // verified_messages_keypair: Option<Keypair>,
    // exact_verified_messages_pubkey: Option<Pubkey>,
    signer_pubkey: Pubkey,
    signer_secret: String,
    transfer_id: String,
    recipient_eth_address: String,
    amount: u64,
    bot_oracle_pubkey: Option<Pubkey>,
) -> CommandResult {
    // let verified_messages_keypair = verified_messages_keypair.unwrap_or_else(Keypair::new);
    // let verified_messages_pubkey =
    //     exact_verified_messages_pubkey.unwrap_or_else(|| verified_messages_keypair.pubkey());

    // println!("Verified messages {}", verified_messages_pubkey);

    let decoded_recipient_address =
        <[u8; 20]>::from_hex(recipient_eth_address).expect(HEX_ETH_ADDRESS_DECODING_ERROR);

    let message = if let Some(bot_oracle_pubkey) = bot_oracle_pubkey {
        let bot_oracle_account = config.rpc_client.get_account_data(&bot_oracle_pubkey)?;
        let bot_oracle = SenderAccount::unpack(bot_oracle_account.as_slice())?;

        println!("Signing as normal sender");
        // Sender message
        [
            decoded_recipient_address.as_ref(),
            b"_".as_ref(),
            amount.to_le_bytes().as_ref(),
            b"_".as_ref(),
            &transfer_id.as_bytes(),
            b"_".as_ref(),
            bot_oracle.eth_address.as_ref(),
        ]
        .concat()
    } else {
        println!("Signing as bot oracle!");
        // Bot oracle message
        [
            decoded_recipient_address.as_ref(),
            b"_".as_ref(),
            amount.to_le_bytes().as_ref(),
            b"_".as_ref(),
            &transfer_id.as_bytes(),
        ]
        .concat()
    };

    let mut instructions = Vec::new();
    // let verified_messages_balance = config
    //     .rpc_client
    //     .get_minimum_balance_for_rent_exemption(VerifiedMessages::LEN)?;

    // if exact_verified_messages_pubkey.is_none() {
    //     instructions.push(system_instruction::create_account(
    //         &config.fee_payer.pubkey(),
    //         &verified_messages_pubkey,
    //         verified_messages_balance,
    //         VerifiedMessages::LEN as u64,
    //         &audius_reward_manager::id(),
    //     ));
    //     signers.push(&verified_messages_keypair);
    // }

    let decoded_secret = <[u8; 32]>::from_hex(signer_secret).expect(HEX_ETH_SECRET_DECODING_ERROR);
    instructions.push(new_secp256k1_instruction_2_0(
        &secp256k1::SecretKey::parse(&decoded_secret)?,
        message.as_ref(),
        instructions.len() as u8,
    ));

    instructions.push(
        verify_transfer_signature(
            &audius_reward_manager::id(),
            &reward_manager_pubkey,
            &signer_pubkey,
            &config.fee_payer.pubkey(),
            transfer_id
        )
    ?);

    let signers = vec![config.fee_payer.as_ref(), config.owner.as_ref()];
    let transaction = CustomTransaction {
        instructions,
        signers,
    };

    transaction.sign(config, 0)
}

#[allow(clippy::too_many_arguments)]
fn command_transfer(
    config: &Config,
    reward_manager_pubkey: Pubkey,
    verified_messages_pubkey: Pubkey,
    bot_oracle_pubkey: Pubkey,
    transfer_id: String,
    recipient_eth_address: String,
    amount: u64,
) -> CommandResult {
    let reward_manager = config.rpc_client.get_account_data(&reward_manager_pubkey)?;
    let reward_manager = RewardManager::unpack(reward_manager.as_slice())?;
    println!("RewardManager num votes: {:?}", reward_manager.min_votes);

    let verified_messages = config.rpc_client.get_account_data(&verified_messages_pubkey)?;
    let verified_messages = VerifiedMessages::unpack(verified_messages.as_slice())?;
    println!("VerifiedMsgs reward_manager: {:?}", verified_messages.reward_manager);
    println!("VerifiedMsgs number of messages: {:?}", verified_messages.messages.len());
    println!("VerifiedMsgs : {:?}", verified_messages);

    let decoded_recipient_address =
        <[u8; 20]>::from_hex(recipient_eth_address).expect(HEX_ETH_ADDRESS_DECODING_ERROR);

    let mut instructions = Vec::new();

    let token_account = config
        .rpc_client
        .get_account_data(&reward_manager.token_account)?;
    let token_account = Account::unpack(token_account.as_slice())?;

    let claimable_token = get_address_pair(
        &claimable_tokens::id(),
        &token_account.mint,
        decoded_recipient_address,
    )?;
    // Checking if the derived address of recipient does not exist
    // then we must add instruction to create it
    let derived_token = config
        .rpc_client
        .get_account_data(&claimable_token.derive.address);
    if derived_token.is_err() {
        instructions.push(claimable_tokens::instruction::init(
            &claimable_tokens::id(),
            &config.fee_payer.pubkey(),
            &token_account.mint,
            claimable_tokens::instruction::CreateTokenAccount {
                eth_address: decoded_recipient_address,
            },
        )?);

        println!(
            "Create new derived token account for recipient: {:?}",
            claimable_token.derive.address
        );
    }

    instructions.push(transfer(
        &audius_reward_manager::id(),
        &verified_messages_pubkey,
        &reward_manager_pubkey,
        &reward_manager.token_account,
        &claimable_token.derive.address,
        &bot_oracle_pubkey,
        &config.fee_payer.pubkey(),
        amount,
        transfer_id,
        decoded_recipient_address,
    )?);

    let transaction = CustomTransaction {
        instructions,
        signers: vec![config.fee_payer.as_ref(), config.owner.as_ref()],
    };

    transaction.sign(config, 0)
}

fn main() {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(&config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .validator(is_url)
                .help("JSON RPC URL for the cluster.  Default from the configuration file."),
        )
        .arg(
            Arg::with_name("owner")
                .long("owner")
                .value_name("KEYPAIR")
                .validator(is_keypair)
                .takes_value(true)
                .help(
                    "Specify the market/pool's owner. \
                     This may be a keypair file, the ASK keyword. \
                     Defaults to the client keypair.",
                ),
        )
        .arg(
            Arg::with_name("fee_payer")
                .long("fee-payer")
                .value_name("KEYPAIR")
                .validator(is_keypair)
                .takes_value(true)
                .help(
                    "Specify the fee-payer account. \
                     This may be a keypair file, the ASK keyword. \
                     Defaults to the client keypair.",
                ),
        )
        .subcommand(SubCommand::with_name("init").about("Init a new reward manager")
            .arg(
                Arg::with_name("reward_manager_keypair")
                    .long("keypair")
                    .validator(is_keypair_or_ask_keyword)
                    .value_name("PATH")
                    .takes_value(true)
                    .help("Reward manager keypair [default: new keypair]"),
            )
            .arg(
                Arg::with_name("token-mint")
                    .long("token-mint")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Mint with which the new token account will be associated on initialization."),
            )
            .arg(
                Arg::with_name("min-votes")
                    .long("min-votes")
                    .validator(is_parsable::<u8>)
                    .takes_value(true)
                    .required(true)
                    .help("Number of signer votes required for sending rewards."),
            ))
        .subcommand(SubCommand::with_name("create-sender").about("Admin method creating new authorized sender")
            .arg(
                Arg::with_name("reward-manager")
                    .long("reward-manager")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Reward manager"),
            )
            .arg(
                Arg::with_name("eth-sender-address")
                    .long("eth-sender-address")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum sender address"),
            )
            .arg(
                Arg::with_name("eth-operator-address")
                    .long("eth-operator-address")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum operator address"),
            ))
        .subcommand(SubCommand::with_name("delete-sender").about("Admin method deleting sender")
            .arg(
                Arg::with_name("reward-manager")
                    .long("reward-manager")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Reward manager"),
            )
            .arg(
                Arg::with_name("eth-sender-address")
                    .long("eth-sender-address")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum sender address"),
            ))
        .subcommand(SubCommand::with_name("add-sender").about("Add new sender")
            .arg(
                Arg::with_name("reward-manager")
                    .long("reward-manager")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Reward manager"),
            )
            .arg(
                Arg::with_name("new-sender")
                    .long("new-sender")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("New Ethereum sender address"),
            )
            .arg(
                Arg::with_name("operator-address")
                    .long("operator-address")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum operator address"),
            )
            .arg(
                Arg::with_name("senders-secrets")
                .long("senders-secrets")
                .validator(is_csv_file)
                .value_name("PATH")
                .takes_value(true)
                .required(true)
                .help("CSV file with senders Ethereum secret keys"),
            ))
        .subcommand(SubCommand::with_name("verify-transfer-signature").about("Verify trasnfer signature")
            .arg(
                Arg::with_name("reward_manager")
                    .long("reward-manager")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Reward manager"),
            )
            .arg(
                Arg::with_name("verified_messages_keypair")
                    .long("keypair")
                    .validator(is_keypair_or_ask_keyword)
                    .value_name("PATH")
                    .takes_value(true)
                    .help("Verified messages keypair [default: new keypair]"),
            )
            .arg(
                Arg::with_name("verified_messages_pubkey")
                    .long("verified-messages-pubkey")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .conflicts_with("keypair")
                    .help("Verified messages"),
            )
            .arg(
                Arg::with_name("address")
                    .long("address")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Signer address"),
            )
            .arg(
                Arg::with_name("secret")
                    .long("secret")
                    .validator(is_hex)
                    .value_name("ETH_SECRET")
                    .takes_value(true)
                    .required(true)
                    .help("Signer ethereum secret key"),
            )
            .arg(
                Arg::with_name("transfer_id")
                    .long("transfer-id")
                    .validator(is_parsable::<String>)
                    .value_name("STRING")
                    .takes_value(true)
                    .required(true)
                    .help("Transfer ID"),
            )
            .arg(
                Arg::with_name("recipient_eth_address")
                    .long("recipient")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Recipient ethereum address"),
            )
            .arg(
                Arg::with_name("amount")
                    .long("amount")
                    .validator(is_parsable::<f64>)
                    .value_name("NUMBER")
                    .takes_value(true)
                    .required(true)
                    .help("Amount to transfer"),
            )
            .arg(
                Arg::with_name("bot_oracle")
                    .long("bot-oracle")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Bot oracle reference (if it doesn't exist - the message will be signed as bot oracle"),
            ))
        .subcommand(SubCommand::with_name("transfer").about("Make transfer")
            .arg(
                Arg::with_name("reward_manager")
                    .long("reward-manager")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Reward manager"),
            )
            .arg(
                Arg::with_name("verified_messages")
                    .long("verified-messages")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Verified messages"),
            )
            .arg(
                Arg::with_name("transfer_id")
                    .long("transfer-id")
                    .validator(is_parsable::<String>)
                    .value_name("STRING")
                    .takes_value(true)
                    .required(true)
                    .help("Transfer ID"),
            )
            .arg(
                Arg::with_name("recipient_eth_address")
                    .long("recipient")
                    .validator(is_eth_address)
                    .value_name("ETH_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Recipient Ethereum address"),
            )
            .arg(
                Arg::with_name("amount")
                    .long("amount")
                    .validator(is_parsable::<f64>)
                    .value_name("NUMBER")
                    .takes_value(true)
                    .required(true)
                    .help("Amount to transfer"),
            )
            .arg(
                Arg::with_name("bot_oracle")
                    .long("bot-oracle")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Bot oracle"),
            ))
        .get_matches();

    let mut wallet_manager = None;
    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };
        let json_rpc_url = value_t!(matches, "json_rpc_url", String)
            .unwrap_or_else(|_| cli_config.json_rpc_url.clone());

        let owner = signer_from_path(
            &matches,
            &cli_config.keypair_path,
            "owner",
            &mut wallet_manager,
        )
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });
        let fee_payer = signer_from_path(
            &matches,
            &cli_config.keypair_path,
            "fee_payer",
            &mut wallet_manager,
        )
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });
        let verbose = matches.is_present("verbose");

        Config {
            rpc_client: RpcClient::new(json_rpc_url),
            verbose,
            owner,
            fee_payer,
            commitment_config: CommitmentConfig::confirmed(),
        }
    };

    solana_logger::setup_with_default("solana=info");

    let _ = match matches.subcommand() {
        ("init", Some(arg_matches)) => {
            let reward_manager_keypair = keypair_of(arg_matches, "reward_manager_keypair");
            let token_mint: Pubkey = pubkey_of(arg_matches, "token-mint").unwrap();
            let min_votes: u8 = value_t_or_exit!(arg_matches, "min-votes", u8);
            command_init(&config, reward_manager_keypair, token_mint, min_votes)
        }
        ("create-sender", Some(arg_matches)) => {
            let reward_manager: Pubkey = pubkey_of(arg_matches, "reward-manager").unwrap();
            let eth_sender_address: String =
                value_t_or_exit!(arg_matches, "eth-sender-address", String);
            let eth_operator_address: String =
                value_t_or_exit!(arg_matches, "eth-operator-address", String);
            command_create_sender(
                &config,
                reward_manager,
                String::from(eth_sender_address.get(2..).unwrap()),
                String::from(eth_operator_address.get(2..).unwrap()),
            )
        }
        ("delete-sender", Some(arg_matches)) => {
            let reward_manager: Pubkey = pubkey_of(arg_matches, "reward-manager").unwrap();
            let eth_sender_address: String =
                value_t_or_exit!(arg_matches, "eth-sender-address", String);
            command_delete_sender(
                &config,
                reward_manager,
                String::from(eth_sender_address.get(2..).unwrap()),
            )
        }
        ("add-sender", Some(arg_matches)) => {
            let reward_manager: Pubkey = pubkey_of(arg_matches, "reward-manager").unwrap();
            let new_sender: String = value_t_or_exit!(arg_matches, "new-sender", String);
            let operator_address: String =
                value_t_or_exit!(arg_matches, "operator-address", String);
            let senders_secrets: String = value_t_or_exit!(arg_matches, "senders-secrets", String);
            command_add_sender(
                &config,
                reward_manager,
                String::from(new_sender.get(2..).unwrap()),
                String::from(operator_address.get(2..).unwrap()),
                senders_secrets,
            )
        }
        ("verify-transfer-signature", Some(arg_matches)) => {
            let reward_manager: Pubkey = pubkey_of(arg_matches, "reward_manager").unwrap();
            // let verified_messages_keypair = keypair_of(arg_matches, "verified_messages_keypair");
            // let verified_messages_pubkey = pubkey_of(arg_matches, "verified_messages_pubkey");
            let signer_pubkey: Pubkey = pubkey_of(arg_matches, "address").unwrap();
            let signer_secret: String = value_t_or_exit!(arg_matches, "secret", String);
            let transfer_id: String = value_t_or_exit!(arg_matches, "transfer_id", String);
            let recipient_eth_address: String =
                value_t_or_exit!(arg_matches, "recipient_eth_address", String);
            let amount: f64 = value_t_or_exit!(arg_matches, "amount", f64);
            let amount = ui_amount_to_amount(amount, spl_token::native_mint::DECIMALS);
            let bot_oracle_pubkey = pubkey_of(arg_matches, "bot_oracle");

            command_verify_transfer_signature(
                &config,
                reward_manager,
                // verified_messages_keypair,
                // verified_messages_pubkey,
                signer_pubkey,
                signer_secret,
                transfer_id,
                String::from(recipient_eth_address.get(2..).unwrap()),
                amount,
                bot_oracle_pubkey,
            )
        }
        ("transfer", Some(arg_matches)) => {
            let reward_manager: Pubkey = pubkey_of(arg_matches, "reward_manager").unwrap();
            let verified_messages = pubkey_of(arg_matches, "verified_messages").unwrap();
            let transfer_id: String = value_t_or_exit!(arg_matches, "transfer_id", String);
            let recipient_eth_address: String =
                value_t_or_exit!(arg_matches, "recipient_eth_address", String);
            let amount: f64 = value_t_or_exit!(arg_matches, "amount", f64);
            let amount = ui_amount_to_amount(amount, spl_token::native_mint::DECIMALS);
            let bot_oracle: Pubkey = pubkey_of(arg_matches, "bot_oracle").unwrap();

            command_transfer(
                &config,
                reward_manager,
                verified_messages,
                bot_oracle,
                transfer_id,
                String::from(recipient_eth_address.get(2..).unwrap()),
                amount,
            )
        }
        _ => unreachable!(),
    }
    .and_then(|transaction| {
        if let Some(transaction) = transaction {
            let signature = config
                .rpc_client
                .send_and_confirm_transaction_with_spinner_and_commitment(
                    &transaction,
                    config.commitment_config,
                )?;
            println!("Signature: {}", signature);
        }
        Ok(())
    })
    .map_err(|err| {
        eprintln!("{:?}", err);
        exit(2)
    });
}

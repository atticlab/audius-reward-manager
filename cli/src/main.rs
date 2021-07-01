mod utils;
use clap::{
    crate_description, crate_name, crate_version, value_t, value_t_or_exit, App, AppSettings, Arg,
    SubCommand,
};

use solana_clap_utils::{
    input_parsers::pubkey_of,
    input_validators::{is_keypair, is_parsable, is_pubkey, is_url},
    keypair::signer_from_path,
};
use solana_client::rpc_client::RpcClient;
use solana_program::{pubkey::Pubkey, instruction::Instruction};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::lamports_to_sol,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
    program_pack::Pack,
};
use std::process::exit;
use audius_reward_manager::{state::RewardManager, instruction::{init}};
use spl_token::state::Account;
use utils::Transaction as CustomTransaction;

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

fn command_init(config: &Config, token_mint: Pubkey, min_votes: u8) -> CommandResult {
    let mut instructions: Vec<Instruction> = Vec::new();

    let reward_manager_acc = Keypair::new();
    println!("Reward manager key created: {:?}", reward_manager_acc.pubkey());

    let reward_manager_acc_balance = config
        .rpc_client
        .get_minimum_balance_for_rent_exemption(RewardManager::LEN)?;
    
    instructions.push(system_instruction::create_account(
        &config.fee_payer.pubkey(),
        &reward_manager_acc.pubkey(),
        reward_manager_acc_balance,
        RewardManager::LEN as u64,
        &audius_reward_manager::id(),
    ));

    let reward_manager_token_acc = Keypair::new();
    println!("Reward manager token key created: {:?}", reward_manager_token_acc.pubkey());

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

    instructions.push(
        init(&audius_reward_manager::id(), &reward_manager_acc.pubkey(), &reward_manager_token_acc.pubkey(), &token_mint, &config.owner.pubkey(), min_votes).unwrap()
    );

    let transaction = CustomTransaction {
        instructions: instructions.clone(),
        signers: vec![
            config.fee_payer.as_ref(),
            config.owner.as_ref(),
            &reward_manager_acc,
            &reward_manager_token_acc,
        ],
    };

    transaction.sign(config, reward_manager_acc_balance + token_acc_balance)
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
                Arg::with_name("token-mint")
                    .long("token-mint")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help(" Mint with which the new token account will be associated on initialization."),
            )
            .arg(
                Arg::with_name("min-votes")
                    .long("min-votes")
                    .validator(is_parsable::<u8>)
                    .takes_value(true)
                    .required(true)
                    .help("Number of signer votes required for sending rewards."),
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
            let token_mint: Pubkey = pubkey_of(arg_matches, "token-mint").unwrap();
            let min_votes: u8 = value_t_or_exit!(arg_matches, "min-votes", u8);
            command_init(&config, token_mint, min_votes)
        },
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
        eprintln!("{}", err);
        exit(1);
    });
}

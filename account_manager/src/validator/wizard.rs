use crate::VALIDATOR_DIR_FLAG;
use account_utils::{eth2_wallet::WalletBuilder, ZeroizeString};
use clap::{App, Arg, ArgMatches};
use console::Term;
use environment::Environment;
use eth2_wallet::bip39::{Language, Mnemonic, MnemonicType};
use std::path::PathBuf;
use types::EthSpec;
use validator_dir::Builder as ValidatorDirBuilder;

pub const CMD: &str = "wizard";
pub const STDIN_PASSWORD_FLAG: &str = "stdin-passwords";

pub const PASSWORD_PROMPT: &str = "Enter a password, or press enter to omit a password:";

pub const DOMAIN: &str = "http://localhost:4242";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Easily create validators sharing a common mnemonic and passphrase.")
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path where the validator directories will be created. \
                    Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, mut env: Environment<T>) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;
    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        VALIDATOR_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;

    let term = Term::stdout();
    term.write_line(
        "Lighthouse Eth2 Validator Wizard \n\
        \n\
        How many validators do you wish to create?",
    )
    .map_err(|e| e.to_string())?;

    let count: usize = read_until_ok(&term, |val| {
        val.parse().map_err(|_| "Not a valid number.".to_string())
    })?;

    if count == 0 {
        term.write_line("Nothing to do.")
            .map_err(|e| e.to_string())?;

        return Ok(());
    }

    let password = loop {
        term.write_line(
            "\n\
            Enter the password that protects the validator secret key:",
        )
        .map_err(|e| e.to_string())?;

        let password = read_secure_until_ok(&term, |val| {
            let pass = ZeroizeString::from(val);

            if pass.as_str().len() < 8 {
                return Err("Password must be 8 or more characters.".to_string());
            }

            Ok(pass)
        })?;

        term.write_line("Please confirm the password:")
            .map_err(|e| e.to_string())?;

        let confirmation = term
            .read_secure_line()
            .map(ZeroizeString::from)
            .map_err(|e| e.to_string())?;

        if password == confirmation {
            break password;
        } else {
            term.write_line("Passwords do not match.")
                .map_err(|e| e.to_string())?;
        }
    };

    let mnemonic = loop {
        term.clear_screen().map_err(|e| e.to_string())?;

        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);

        term.write_line(
            "This is your seed phrase. You must store it safely since it has full \
                control of your staked ETH and is the only way to withdraw it.\n\
                \n\
                Storing your seed phrase *only on paper* and in multiple, secure locations \
                is recommended.\
                \n\n\n",
        )
        .map_err(|e| e.to_string())?;

        term.write_line(mnemonic.phrase())
            .map_err(|e| e.to_string())?;

        term.write_line("\n\n\nPress any key when you have recorded your seed phrase.")
            .map_err(|e| e.to_string())?;

        term.read_line().map_err(|e| e.to_string())?;
        term.clear_screen().map_err(|e| e.to_string())?;

        term.write_line("Please re-enter your mnemonic to ensure it was recorded correctly.")
            .map_err(|e| e.to_string())?;

        let confirmation = term
            .read_line()
            .map(ZeroizeString::from)
            .map_err(|e| e.to_string())?;

        if mnemonic.phrase() == confirmation.as_str() {
            break mnemonic;
        } else {
            term.write_line("Mnemonic does not match.")
                .map_err(|e| e.to_string())?;
        }
    };

    term.clear_screen().map_err(|e| e.to_string())?;

    term.write_line("Generating deterministic EIP-2386 wallet...")
        .map_err(|e| e.to_string())?;

    let mut wallet = WalletBuilder::from_mnemonic(
        &mnemonic,
        password.as_ref(),
        "Temporary Wizard Wallet".into(),
    )
    .map_err(|e| format!("Unable to start building wallet: {:?}", e))?
    .build()
    .map_err(|e| format!("Unable to generate wallet: {:?}", e))?;

    let mut validator_dirs = Vec::with_capacity(count);

    for i in 0..count {
        term.write_line(&format!(
            "Generating encrypted EIP-2335 keystore {}/{}...",
            i + 1,
            count
        ))
        .map_err(|e| e.to_string())?;

        let keystores = wallet
            .next_validator(password.as_ref(), password.as_ref(), password.as_ref())
            .map_err(|e| format!("Unable to validator keystore: {:?}", e))?;

        term.write_line(&format!(
            "Creating validator directory {}/{}...",
            i + 1,
            count
        ))
        .map_err(|e| e.to_string())?;

        // TODO: save passwords in validator defs.
        // TODO: allow custom eth deposit amount.

        let validator_dir = ValidatorDirBuilder::new(validator_dir.clone())
            .voting_keystore(keystores.voting, password.as_ref())
            .withdrawal_keystore(keystores.withdrawal, password.as_ref())
            .create_eth1_tx_data(32_000_000_000, &spec)
            .store_withdrawal_keystore(false)
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        validator_dirs.push(validator_dir);
    }

    term.clear_screen().map_err(|e| e.to_string())?;

    term.write_line(&format!("Created {} validators!\n", count))
        .map_err(|e| e.to_string())?;

    term.write_line(
        "If you would like to use Metamask in your web browser to submit \
        deposits enter 'y' now, this is the simplest option.\
        \n\n\
        Otherwise, enter 'n' \
        to submit deposits via `lighthouse account validator deposit` or some \
        other method.\
        \n\n\
        Enter 'y' or 'n':",
    )
    .map_err(|e| e.to_string())?;

    let display_urls = read_until_ok(&term, |val| match val.as_ref() {
        "y" | "Y" => Ok(true),
        "n" | "N" => Ok(false),
        _ => Err("Must provide nothing or 'done'.".to_string()),
    })?;

    term.clear_screen().map_err(|e| e.to_string())?;

    if count > 1 {
        term.write_line(&format!(
            "You will be displayed {} links, click each one and submit a \
            Metamask transaction. \
            \n\n\
            Only submit deposits to the sigmaprime.io domain, look for the \
            HTTPS icon in your browser!\
            \n\n\
            Press enter to continue.\
            \n",
            count
        ))
        .map_err(|e| e.to_string())?;
        term.read_line().map_err(|e| e.to_string())?;
    }

    if display_urls {
        for (i, validator_dir) in validator_dirs.iter().enumerate() {
            term.clear_screen().map_err(|e| e.to_string())?;

            let eth1_deposit_data = validator_dir
                .eth1_deposit_data()
                .map_err(|e| format!("Failed to read deposit data for new validator: {:?}", e))?
                .ok_or_else(|| "No deposit data for new validator".to_string())?;

            term.write_line(&format!(
                "Validator Deposit Link {} of {} \
                \n\n\
                {}/deposit-medalla.html?txData=0x{}\
                \n\n\
                Press enter when you have clicked the link and submitted \
                a deposit of Goerli ETH via Metamask.",
                i + 1,
                count,
                DOMAIN,
                hex::encode(eth1_deposit_data.rlp),
            ))
            .map_err(|e| e.to_string())?;

            term.read_line().map_err(|e| e.to_string())?;
        }
    }

    term.clear_screen().map_err(|e| e.to_string())?;

    term.write_line(
        "The process is complete!.\
        \n\n\
        Use a Lighthouse validator client to start staking with these validators.\
        \n\n\
        Press any key to exit.",
    )
    .map_err(|e| e.to_string())?;

    term.read_line().map_err(|e| e.to_string())?;

    Ok(())
}

/// Generate a function that will keep reading a line until a parsing function returns `Ok`.
macro_rules! read_until_fn {
    ($title: ident, $read_fn: ident) => {
        fn $title<T, F>(term: &Term, mut parse: F) -> Result<T, String>
        where
            F: FnMut(String) -> Result<T, String>,
        {
            loop {
                let line = term.$read_fn().map_err(|e| e.to_string())?;
                match parse(line) {
                    Ok(val) => break Ok(val),
                    Err(e) => term.write_line(&e).map_err(|e| e.to_string())?,
                }
            }
        }
    };
}

read_until_fn!(read_until_ok, read_line);
read_until_fn!(read_secure_until_ok, read_secure_line);

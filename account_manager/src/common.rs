use account_utils::read_input_from_user;

pub const WALLET_NAME_PROMPT: &str = "Enter wallet name:";

/// Reads in a wallet name from the user. If the `--wallet-name` flag is provided, use it. Otherwise
/// read from an interactive prompt using tty unless the `--stdin-inputs` flag is provided.
pub fn read_wallet_name_from_cli(
    wallet_name: Option<String>,
    stdin_inputs: bool,
) -> Result<String, String> {
    match wallet_name {
        Some(name) => Ok(name),
        None => {
            eprintln!("{}", WALLET_NAME_PROMPT);

            read_input_from_user(stdin_inputs)
        }
    }
}

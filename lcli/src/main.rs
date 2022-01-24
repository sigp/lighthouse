use lcli::new_app;
use std::process;

fn main() {
    env_logger::init();

    let matches = new_app().get_matches();

    let result = lcli::run(&matches);

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            println!("Failed to run lcli: {}", e);
            process::exit(1)
        }
    }
}

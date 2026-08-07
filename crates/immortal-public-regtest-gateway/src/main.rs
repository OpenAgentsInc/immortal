//! Public-regtest gateway process. It has one closed command and no CLI for
//! worker, wallet, rail, filesystem, or RPC operations.

fn main() {
    match immortal_public_regtest_gateway::run_server() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("immortal-public-regtest-gateway: {error}");
            std::process::exit(1);
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        #[cfg(feature = "no-spend")]
        [mode] if mode == "--no-spend" => immortal_provider::no_spend::run(),
        #[cfg(feature = "funded")]
        [command] if command == "run" => immortal_provider::funded::run(),
        #[cfg(feature = "funded")]
        [command] if command == "address" => {
            println!("{}", immortal_provider::funded::receive_address()?);
            Ok(())
        }
        #[cfg(feature = "funded")]
        [command] if command == "ark-transfer" => immortal_provider::funded::ark_transfer(),
        #[cfg(any(feature = "funded", feature = "no-spend"))]
        [command] if command == "contract" => {
            use std::io::Write;

            let bytes = immortal_provider::contract::provider_contract_bytes()
                .map_err(|error| error.to_string())?;
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|error| format!("could not write provider contract: {error}"))
        }
        _ => Err(
            "usage: immortal-provider <run|address|ark-transfer|contract|--no-spend>".to_owned(),
        ),
    }
}

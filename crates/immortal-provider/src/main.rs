fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() != ["--no-spend"] {
        return Err("usage: immortal-provider --no-spend".to_owned());
    }
    immortal_provider::no_spend::run()
}

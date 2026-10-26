fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--worker") => std::process::exit(novul_lib::worker::main(args[1..].to_vec())),
        Some(
            "findings" | "finding" | "projects" | "scan" | "mcp" | "help" | "--help" | "--version",
        ) => std::process::exit(novul_lib::cli::main(args)),
        _ => novul_lib::run(),
    }
}

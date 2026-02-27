use clap::{arg, Arg, Command};

pub(crate) fn init() {
    let cmd = Command::new("s").args(generate_args());
    let matches = cmd.try_get_matches()
        .unwrap_or_else(|e| e.exit());

    println!("Input: {}", matches.get_one::<String>("input").unwrap())
}

fn generate_args() -> Vec<Arg> {
    vec![
        arg!(--input <PCAP_FILE> "(required) path to a pcap file").required(true),
        arg!(--output <JSON_FILE> "(optional) — path to write the report").required(false),
        arg!(--filter <protocol> "(optional) — e.g., tcp, udp, icmp").required(false),
        arg!(--verbose)
    ]
}
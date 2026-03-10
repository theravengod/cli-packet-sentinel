use crate::runcfg::RunCfg;
use clap::{arg, Arg, Command};
use colored::Colorize;

pub(crate) fn init() {
    let cmd = Command::new("s").args(generate_args());
    let matches = cmd.try_get_matches()
        .unwrap_or_else(|e| e.exit());

    let cfg = RunCfg::from_params(matches);
    exec(&cfg)
}

fn generate_args() -> Vec<Arg> {
    vec![
        arg!(-i --input <PCAP_FILE> "(required) path to a pcap file").required(true),
        arg!(-o --output <JSON_FILE> "(optional) — path to write the report").required(false),
        arg!(-f --filter <protocol> "(optional) — e.g., tcp, udp, icmp").required(false),
        arg!(-v --verbose)
    ]
}

fn exec(cfg: &RunCfg) {
    if cfg.is_verbose {
        println!("Input: {}", cfg.input_file.bright_blue());
        println!("Output: {}", cfg.output_file.bright_green());
        if cfg.filter_protocol.is_some() {
            println!("Filter: {}", cfg.filter_protocol.clone().unwrap());
        }
    }

    // TODO: just do the work here
}
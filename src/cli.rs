use crate::parser::pcap::PcapReader;
use crate::runcfg::RunCfg;
use clap::{Arg, Command, arg};
use colored::Colorize;
use std::fs::File;
use std::io::BufReader;

pub(crate) fn init() {
    let cmd = Command::new("s").args(generate_args());
    let matches = cmd.try_get_matches().unwrap_or_else(|e| e.exit());

    let cfg = RunCfg::from_params(&matches);
    exec(&cfg)
}

fn generate_args() -> Vec<Arg> {
    vec![
        arg!(-i --input <PCAP_FILE> "(required) path to a pcap file").required(true),
        arg!(-o --output <JSON_FILE> "(optional) — path to write the report").required(false),
        arg!(-f --filter <protocol> "(optional) — e.g., tcp, udp, icmp").required(false),
        arg!(-v - -verbose),
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

    read_pcap_file(&cfg.input_file)
}

fn read_pcap_file(input: &String) {
    match File::open(input) {
        Ok(f) => {
            let reader = BufReader::new(f);
            match PcapReader::new(reader) {
                Ok(reader) => {
                    println!("Analysing the PCAP file ...");
                    println!();
                    if reader.header.network != 1 {
                        eprintln!("[!] This tool only supports Ethernet PCAP files");
                        return;
                    }
                    print!(
                        "[-] Type (byte order): {}",
                        format!("{:?}", reader.header.byte_order).bright_blue()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{}: Parsing PCAP file failed ! Reason: {}",
                        "Error".red(),
                        e
                    )
                }
            }
        }
        Err(e) => {
            eprintln!(
                "{}: Can't open file {} ! Reason: {}",
                "Error".red(),
                input.red(),
                e
            )
        }
    }
}

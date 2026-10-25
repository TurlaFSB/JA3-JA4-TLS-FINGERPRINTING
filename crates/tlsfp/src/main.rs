// ©AngelaMos | 2026
// main.rs

mod case_report;
mod cli;
mod config;
mod deliver;
mod dnsbook;
mod dnsfind;
mod engine;
mod extras;
mod library;
mod live;
mod npcap;
mod report;
mod serve;
mod supervisor;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

fn main() -> Result<()> {
    // `println!` panics when the reader of a pipe goes away (`tlsfp intel
    // alerts | head`). That is not an error worth a backtrace: leave quietly,
    // the way a command line tool is expected to.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let text = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if text.contains("Broken pipe") {
            std::process::exit(0);
        }
        default_hook(info);
    }));

    // Fold the configuration file into the arguments before the real parse,
    // so one parser (and one set of validations) serves flags, variables and file.
    let args = match config::apply(std::env::args_os().collect()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(2);
        }
    };
    let cli = Cli::parse_from(args);
    cli.init_tracing();
    let result = cli.run();
    deliver::flush();
    result
}

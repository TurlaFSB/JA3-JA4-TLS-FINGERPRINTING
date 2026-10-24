// ©AngelaMos | 2026
// main.rs

mod case_report;
mod cli;
mod deliver;
mod extras;
mod library;
mod live;
mod npcap;
mod report;
mod serve;

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

    let cli = Cli::parse();
    cli.init_tracing();
    let result = cli.run();
    deliver::flush();
    result
}

// © Pranav Verma | 2026
// build.rs

//! On Windows (MSVC) the packet capture library is loaded lazily.
//!
//! `wpcap.dll` belongs to Npcap and, in Npcap's default install mode, lives in
//! `System32\Npcap`, which is not on the loader's search path. A normal link
//! would stop the program at start-up with a "DLL not found" dialog before it
//! could print anything, even for commands that never capture. Delay-loading
//! the DLL lets `tlsfp pcap`, `identify` and `html` run on a machine without
//! Npcap, and lets the live commands add the right folder and give a plain
//! message when Npcap is missing (`src/npcap.rs`).

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
    }
    println!("cargo:rerun-if-changed=build.rs");
}

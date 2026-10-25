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
    println!("cargo:rustc-env=TLSFP_BUILD={}", build_id());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}

/// The commit this binary was built from (short hash, `-dirty` when the tree
/// had uncommitted changes), so the dashboard can say which build is running.
/// `unknown` outside a git checkout, for example from a source tarball.
fn build_id() -> String {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    match git(&["rev-parse", "--short=9", "HEAD"]) {
        Some(hash) if !hash.is_empty() => {
            let dirty = git(&["status", "--porcelain"]).is_some_and(|out| !out.is_empty());
            if dirty { format!("{hash}-dirty") } else { hash }
        }
        _ => "unknown".to_owned(),
    }
}

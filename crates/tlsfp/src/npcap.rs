// © Pranav Verma | 2026
// npcap.rs

//! Finding Npcap on Windows before the first capture call.
//!
//! The capture library is delay-loaded (see `build.rs`), so a missing DLL
//! would otherwise surface as a crash at the first call. This checks first,
//! in safe code: Npcap installs `wpcap.dll` in `System32\Npcap`, or in
//! `System32` when installed in WinPcap-compatible mode. When it is in the
//! former, the program restarts itself with that folder on `PATH` so the
//! loader finds it (a safe way to do what `set_var` does unsafely). On other systems there is nothing to do.

/// Makes the capture library loadable, or says why it is not.
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
pub fn ensure() -> Result<(), String> {
    Ok(())
}

/// Makes the capture library loadable, or says why it is not.
#[cfg(windows)]
pub fn ensure() -> Result<(), String> {
    use std::path::PathBuf;

    let root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let system32 = root.join("System32");
    let npcap = system32.join("Npcap");
    if system32.join("wpcap.dll").exists() {
        return Ok(());
    }
    if npcap.join("wpcap.dll").exists() {
        // Changing this process's PATH is unsafe in current Rust, and the
        // loader reads it from the process anyway. Run again as a child that
        // starts with the right PATH and pass its exit code through. The
        // marker stops a second round if the child still cannot load it.
        if std::env::var_os("TLSFP_NPCAP_CHILD").is_some() {
            return Err(format!(
                "Npcap was found in {} but its library would not load; reinstall Npcap",
                npcap.display()
            ));
        }
        let mut paths = vec![npcap];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        let joined = std::env::join_paths(paths).map_err(|error| error.to_string())?;
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        let status = std::process::Command::new(exe)
            .args(std::env::args_os().skip(1))
            .env("PATH", joined)
            .env("TLSFP_NPCAP_CHILD", "1")
            .status()
            .map_err(|error| format!("could not restart with Npcap on the path: {error}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
    Err(
        "live capture on Windows needs Npcap, which is not installed. Install it from https://npcap.com (the default options are fine), then run this again. Reading capture files does not need it."
            .to_owned(),
    )
}

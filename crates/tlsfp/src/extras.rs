// © Pranav Verma | 2026
// extras.rs

//! Process-wide options that apply to every command that detects: the
//! operator's rules file and where alerts are delivered. They are read once at
//! start-up from global flags and consulted where a store is configured, so
//! the many functions that open a store do not each need two more parameters.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use tlsfp_intel::RuleSet;

#[derive(Default)]
struct Extras {
    rules: Option<Arc<RuleSet>>,
}

static EXTRAS: OnceLock<Extras> = OnceLock::new();

/// Loads and validates the rules file, if one was given. Called once, before
/// any command runs; an invalid file stops the program with the reason.
pub fn init(rules: Option<&PathBuf>) -> Result<()> {
    let rules = match rules {
        Some(path) => {
            let set = RuleSet::load(path)
                .map_err(anyhow::Error::msg)
                .context("loading the detection rules")?;
            tracing::info!(rules = set.len(), file = %path.display(), "custom detection rules loaded");
            Some(Arc::new(set))
        }
        None => None,
    };
    let _ = EXTRAS.set(Extras { rules });
    Ok(())
}

/// The operator's rules, when a file was given.
pub fn rules() -> Option<Arc<RuleSet>> {
    EXTRAS.get().and_then(|extras| extras.rules.clone())
}

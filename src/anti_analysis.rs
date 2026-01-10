//! Anti-Analysis Module
//!
//! This module contains functions for detecting virtual machines, sandboxes,
//! and debugging environments.

use crate::generated_signatures;
use crate::SignatureChecker;

/// Checks for anti-analysis signatures and terminates the process if any are found.
pub fn check_and_terminate() {
    let signatures = generated_signatures::get_embedded_signatures();
    let checker = SignatureChecker::new();

    for rule in &signatures.rules {
        if let Ok(true) = rule.matches(&checker) {
            for action in &rule.actions {
                if let crate::Action::Exit { .. } = action {
                    let _ = action.execute();
                }
            }
        }
    }
}

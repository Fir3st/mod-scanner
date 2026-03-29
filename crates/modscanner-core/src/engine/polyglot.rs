use super::{DetectionEngine, FileContext, Finding};

/// Detects polyglot files — files valid as multiple formats simultaneously.
/// Example: a file that is both a valid PNG and a valid ZIP.
pub struct PolyglotEngine;

impl PolyglotEngine {
    pub fn new() -> Self {
        Self
    }
}

impl DetectionEngine for PolyglotEngine {
    fn name(&self) -> &'static str {
        "polyglot"
    }

    fn should_scan(&self, _ctx: &FileContext) -> bool {
        false // TODO: Phase 4
    }

    fn scan(&self, _ctx: &FileContext) -> Vec<Finding> {
        Vec::new() // TODO: Phase 4
    }
}

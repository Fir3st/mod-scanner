pub mod engine;
pub mod file_context;
pub mod report;
pub mod scanner;

use engine::{
    DetectionEngine,
    filetype::FiletypeEngine,
    unicode::UnicodeEngine,
    binary::BinaryEngine,
    static_analysis::StaticAnalysisEngine,
    polyglot::PolyglotEngine,
};

/// Create all detection engines with default configuration
pub fn default_engines() -> Vec<Box<dyn DetectionEngine>> {
    vec![
        Box::new(FiletypeEngine::new()),
        Box::new(UnicodeEngine::new()),
        Box::new(BinaryEngine::new()),
        Box::new(StaticAnalysisEngine::new()),
        Box::new(PolyglotEngine::new()),
    ]
}

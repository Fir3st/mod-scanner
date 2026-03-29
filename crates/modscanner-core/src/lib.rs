pub mod engine;
pub mod file_context;
pub mod report;
pub mod scanner;

use engine::{
    DetectionEngine, binary::BinaryEngine, filetype::FiletypeEngine, polyglot::PolyglotEngine,
    static_analysis::StaticAnalysisEngine, unicode::UnicodeEngine,
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

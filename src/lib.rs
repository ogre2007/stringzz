// lib.rs - Add module docs
#![doc = r##"
# stringzz Library

A high-performance library for extracting strings, opcodes, and metadata from various file formats.

## Features
- ASCII and UTF-16 string extraction
- PE/ELF/DEX opcode extraction
- File metadata and hash calculation
- Configurable deduplication strategies
- Parallel processing support

## Performance
- Zero-copy operations where possible
- Optimized hash map usage
- Lazy regex compilation
- Memory-efficient processing

## Error Handling
Comprehensive error types with automatic Python exception conversion.
"##]

pub mod parsing;
use log::info;
pub use parsing::*;

pub mod types;
pub use types::*;

pub mod processing;
pub use processing::*;

pub mod scoring;
pub use scoring::*;

pub mod err;
pub use err::*;
pub mod config;

pub use config::*;
use pyo3::{
    Bound, PyResult, Python, pymodule,
    types::{PyModule, PyModuleMethods},
    wrap_pyfunction,
};

use rayon::prelude::*;
use std::collections::HashMap;

use pyo3::prelude::*;
use regex::Regex;

#[pyfunction]
pub fn extract_strings(
    file_data: Vec<u8>,
    min_len: usize,
    max_len: Option<usize>,
) -> PyResult<(HashMap<String, TokenInfo>, HashMap<String, TokenInfo>)> {
    let max_len = max_len.unwrap_or(usize::MAX);
    Ok((
        extract_and_count_ascii_strings(&file_data, min_len, max_len),
        extract_and_count_utf16_strings(&file_data, min_len, max_len),
    ))
}

/// Remove non-ASCII characters from bytes, keeping printable ASCII 0x20..0x7E
#[pyfunction]
pub fn remove_non_ascii_drop(data: &[u8]) -> PyResult<String> {
    Ok(data
        .iter()
        .filter(|&&b| b > 31 && b < 127)
        .cloned()
        .map(|x| x.to_string())
        .collect())
}

/// Gets the contents of a file (limited to 1024 characters)
pub fn is_ascii_string(data: &[u8], padding_allowed: bool) -> bool {
    for &b in data {
        if padding_allowed {
            if !((b > 31 && b < 127) || b == 0) {
                return false;
            }
        } else if !(b > 31 && b < 127) {
            return false;
        }
    }
    true
}

/// Check if string is valid base64
#[pyfunction]
pub fn is_base_64(s: String) -> PyResult<bool> {
    if !s.len().is_multiple_of(4) {
        return Ok(false);
    }

    let re = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
    Ok(re.is_match(&s))
}

/// Check if string is hex encoded
#[pyfunction]
pub fn is_hex_encoded(s: String, check_length: bool) -> PyResult<bool> {
    if s.is_empty() {
        Ok(false)
    } else {
        let re = Regex::new(r"^[A-Fa-f0-9]+$").unwrap();

        if !re.is_match(&s) {
            return Ok(false);
        }

        if check_length {
            Ok(s.len().is_multiple_of(2))
        } else {
            Ok(true)
        }
    }
}

#[pyfunction]
#[pyo3(signature = (
        config = None,
        excludegood = false,
        min_score = 5,
        superrule_overlap = 5,
        good_strings_db = None,
        good_opcodes_db = None,
        good_imphashes_db = None,
        good_exports_db = None,
        pestudio_strings = None,
    ))]
pub fn init_analysis(
    config: Option<Config>,
    excludegood: bool,
    min_score: i64,
    superrule_overlap: usize,
    good_strings_db: Option<HashMap<String, usize>>,
    good_opcodes_db: Option<HashMap<String, usize>>,
    good_imphashes_db: Option<HashMap<String, usize>>,
    good_exports_db: Option<HashMap<String, usize>>,
    pestudio_strings: Option<HashMap<String, (i64, String)>>,
) -> PyResult<(FileProcessor, ScoringEngine)> {
    let fp = FileProcessor::new(config)?;
    let good_strings_db = good_strings_db.unwrap();
    let good_opcodes_db = good_opcodes_db.unwrap();
    let good_imphashes_db = good_imphashes_db.unwrap();
    let good_exports_db = good_exports_db.unwrap();
    let pestudio_strings = pestudio_strings.unwrap();

    let scoring_engine = ScoringEngine {
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_strings,
        pestudio_marker: Default::default(),
        base64strings: Default::default(),
        hex_enc_strings: Default::default(),
        reversed_strings: Default::default(),
        excludegood,
        min_score,
        superrule_overlap,
        string_scores: Default::default(),
    };
    Ok((fp, scoring_engine))
}

#[pyfunction]
pub fn process_file(
    malware_path: String,
    mut fp: FileProcessor,
    mut scoring_engine: ScoringEngine,
) -> PyResult<(
    Vec<tokens::TokenInfo>,
    Vec<tokens::TokenInfo>,
    Vec<tokens::TokenInfo>,
    HashMap<String, file_info::FileInfo>,
)> {
    info!("Processing malware file...");
    fp.process_file_with_checks(malware_path);
    let (string_stats, opcodes, utf16strings, file_infos) =
        (fp.strings, fp.opcodes, fp.utf16strings, fp.file_infos);
    let string_stats = scoring_engine.filter_string_set(string_stats.into_values().collect())?;
    let opcodes = scoring_engine.filter_opcode_set(opcodes.into_values().collect())?;
    let utf16strings = scoring_engine.filter_string_set(utf16strings.into_values().collect())?;
    Ok((string_stats, opcodes, utf16strings, file_infos))
}

// Add a new function that returns comprehensive analysis results
#[pyfunction]
pub fn analyze_buffers_comprehensive(
    buffers: Vec<Vec<u8>>,
    fp: PyRefMut<FileProcessor>,
    scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, FileInfo>,
)> {
    // First, process buffers to get aggregated stats
    let results = process_buffers_with_stats(&buffers, fp)?;

    process_results(results, scoring_engine)
}

pub fn process_results(
    results: ProcessingResults,
    mut scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, FileInfo>,
)> {
    let (string_combis, string_superrules, file_strings) = scoring_engine
        .sample_string_evaluation(results.strings)
        .unwrap();
    let (utf16_combis, utf16_superrules, file_utf16strings) = scoring_engine
        .sample_string_evaluation(results.utf16strings)
        .unwrap();
    let mut file_opcodes = Default::default();
    let opcode_combis = Default::default();
    let opcode_superrules = Default::default();
    extract_stats_by_file(&results.opcodes, &mut file_opcodes, None, None);

    let file_strings = file_strings
        .iter()
        .map(|(x, tokens)| {
            (
                x.clone(),
                scoring_engine.filter_string_set(tokens.to_vec()).unwrap(),
            )
        })
        .collect();
    let file_utf16strings = file_utf16strings
        .iter()
        .map(|(x, tokens)| {
            (
                x.clone(),
                scoring_engine.filter_string_set(tokens.to_vec()).unwrap(),
            )
        })
        .collect();
    file_opcodes = file_opcodes
        .iter()
        .map(|(x, tokens)| {
            (
                x.clone(),
                scoring_engine.filter_opcode_set(tokens.to_vec()).unwrap(),
            )
        })
        .collect();

    /*let (opcode_combis, opcode_superrules, file_opcodes) = scoring_engine

    .sample_string_evaluation(scoring_engine.opcodes.clone())
    .unwrap();*/
    Ok((
        string_combis,
        string_superrules,
        utf16_combis,
        utf16_superrules,
        opcode_combis,
        opcode_superrules,
        file_strings,
        file_opcodes,
        file_utf16strings,
        results.file_infos,
    ))
}

#[pyfunction]
pub fn process_malware(
    malware_path: String,
    mut fp: PyRefMut<FileProcessor>,
    scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, FileInfo>,
)> {
    //env_logger::init();
    // Check if we should disable super rules for single files
    env_logger::init_from_env("RUST_LOG");

    info!("Processing malware files...");
    let results = fp.parse_sample_dir(malware_path).unwrap();
    process_results(results, scoring_engine)
}

#[pymodule]
#[pyo3(name = "stringzz")]
fn stringzz(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_strings, m)?)?;
    m.add_function(wrap_pyfunction!(get_file_info, m)?)?;
    m.add_function(wrap_pyfunction!(process_malware, m)?)?;
    m.add_function(wrap_pyfunction!(process_file, m)?)?;

    m.add_function(wrap_pyfunction!(get_pe_info, m)?)?;
    m.add_function(wrap_pyfunction!(remove_non_ascii_drop, m)?)?;
    m.add_function(wrap_pyfunction!(is_base_64, m)?)?;
    m.add_function(wrap_pyfunction!(is_hex_encoded, m)?)?;
    m.add_function(wrap_pyfunction!(init_analysis, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_buffers_comprehensive, m)?)?;

    m.add_class::<TokenInfo>()?;
    m.add_class::<Config>()?;

    m.add_class::<TokenType>()?;
    m.add_class::<FileProcessor>()?;
    m.add_class::<ScoringEngine>()?;

    m.add_class::<Combination>()?;
    m.add_class::<ProcessingResults>()?;

    Ok(())
}

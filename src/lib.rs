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
use std::{
    cmp::min,
    collections::{HashMap, HashSet},
};

use anyhow::Result;

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

pub fn extract_and_count_ascii_strings(
    data: &[u8],
    min_len: usize,
    max_len: usize,
) -> HashMap<String, TokenInfo> {
    let mut current_string = String::new();
    let mut stats: HashMap<String, TokenInfo> = HashMap::new();
    //println!("{:?}", data);
    for &byte in data {
        if (0x20..=0x7E).contains(&byte) && current_string.len() <= max_len {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= min_len {
                stats
                    .entry(current_string.clone())
                    .or_insert(TokenInfo::new(
                        current_string.clone(),
                        0,
                        TokenType::ASCII,
                        HashSet::new(),
                        None,
                    ))
                    .count += 1;
            }
            current_string.clear();
        }
    }
    //println!("{:?}", stats);
    if current_string.len() >= min_len && current_string.len() <= max_len {
        stats
            .entry(current_string.clone())
            .or_insert(TokenInfo::new(
                current_string.clone(),
                0,
                TokenType::ASCII,
                HashSet::new(),
                None,
            ))
            .count += 1;
        assert!(!stats.get(&current_string.clone()).unwrap().reprz.is_empty());
    }
    stats.clone()
}

// Alternative implementation that handles UTF-16 more robustly
pub fn extract_and_count_utf16_strings(
    data: &[u8],
    min_len: usize,
    max_len: usize,
) -> HashMap<String, TokenInfo> {
    let mut current_string = String::new();
    let mut stats: HashMap<String, TokenInfo> = HashMap::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);

        // Handle different cases for UTF-16
        match code_unit {
            // Printable ASCII range
            0x0020..=0x007E => {
                if let Some(ch) = char::from_u32(code_unit as u32) {
                    current_string.push(ch);
                } else {
                    if current_string.len() >= min_len {
                        //println!("UTF16LE: {}", current_string);

                        stats
                            .entry(current_string.clone())
                            .or_insert(TokenInfo::new(
                                current_string.clone(),
                                0,
                                TokenType::UTF16LE,
                                HashSet::new(),
                                None,
                            ))
                            .count += 1;
                    }
                    current_string.clear();
                }
            }
            // Null character or other control characters - end of string
            _ => {
                if current_string.len() >= min_len {
                    stats
                        .entry(current_string.clone())
                        .or_insert(TokenInfo::new(
                            current_string.clone(),
                            0,
                            TokenType::UTF16LE,
                            HashSet::new(),
                            None,
                        ))
                        .count += 1;
                }
                current_string.clear();
            }
        }

        i += 2;
    }

    // Final string
    if current_string.len() >= min_len {
        stats
            .entry(current_string[..min(max_len, current_string.len())].to_owned())
            .or_insert(TokenInfo::new(
                current_string.clone(),
                0,
                TokenType::UTF16LE,
                HashSet::new(),
                None,
            ))
            .count += 1;

        if current_string.len() as i64 - max_len as i64 >= min_len as i64 {
            stats
                .entry(current_string[max_len..].to_owned())
                .or_insert(TokenInfo::new(
                    current_string.clone(),
                    0,
                    TokenType::UTF16LE,
                    HashSet::new(),
                    None,
                ))
                .count += 1;
        }
    }
    stats
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
        excludegood = true,
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
pub fn process_buffer(
    buffer: Vec<u8>,
    fp: PyRefMut<FileProcessor>,
    mut scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, FileInfo>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
)> {
    let file_name = "data";
    let mut file_infos = HashMap::new();

    let (fi, string_stats, utf16strings, opcodes) = processing::process_buffer_u8(
        buffer[..min(fp.config.max_file_size_mb * 1024 * 1024, buffer.len())].to_vec(),
        &fp.config,
    )
    .unwrap();
    let mut file_strings = HashMap::new();
    file_strings.insert(
        file_name.to_string(),
        scoring_engine.filter_string_set(string_stats.into_values().collect())?,
    );

    let mut file_utf16strings = HashMap::new();
    file_utf16strings.insert(
        file_name.to_string(),
        scoring_engine.filter_string_set(utf16strings.into_values().collect())?,
    );
    let mut file_opcodes = HashMap::new();
    file_opcodes.insert(
        file_name.to_string(),
        scoring_engine.filter_string_set(opcodes.into_values().collect())?,
    );
    file_infos.insert(file_name.to_string(), fi);
    Ok((file_infos, file_strings, file_opcodes, file_utf16strings))
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

#[pyfunction]
pub fn process_buffers_parallel(
    buffers: Vec<Vec<u8>>,
    fp: PyRefMut<FileProcessor>,
    mut scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, FileInfo>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
)> {
    if buffers.is_empty() {
        return Ok((
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        ));
    }

    let config = fp.config.clone();
    let max_file_size = config.max_file_size_mb * 1024 * 1024;

    // Process buffers in parallel
    let results: Vec<
        Result<(
            FileInfo,
            HashMap<String, TokenInfo>,
            HashMap<String, TokenInfo>,
            HashMap<String, TokenInfo>,
        )>,
    > = buffers
        .par_iter()
        .enumerate()
        .map(|(i, buffer)| {
            // Limit buffer size
            let limited_buffer = if buffer.len() > max_file_size {
                buffer[..max_file_size].to_vec()
            } else {
                buffer.clone()
            };

            process_buffer_u8(limited_buffer, &config)
                .map_err(|e| anyhow::anyhow!("Failed to process buffer {}: {}", i, e))
        })
        .collect();

    // Collect results
    let mut file_infos = HashMap::new();
    let mut all_strings = HashMap::new();
    let mut all_utf16strings = HashMap::new();
    let mut all_opcodes = HashMap::new();

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok((fi, strings, utf16strings, opcodes)) => {
                let file_name = format!("buffer_{}", i);
                file_infos.insert(file_name.clone(), fi);

                // Add file reference to token infos
                let mut file_strings = HashMap::new();
                let mut file_utf16strings = HashMap::new();
                let mut file_opcodes = HashMap::new();

                for (_, mut ti) in strings {
                    ti.files.insert(file_name.clone());
                    file_strings.insert(ti.reprz.clone(), ti);
                }

                for (_, mut ti) in utf16strings {
                    ti.files.insert(file_name.clone());
                    file_utf16strings.insert(ti.reprz.clone(), ti);
                }

                for (_, mut ti) in opcodes {
                    ti.files.insert(file_name.clone());
                    file_opcodes.insert(ti.reprz.clone(), ti);
                }

                // Filter strings through scoring engine
                let filtered_strings =
                    scoring_engine.filter_string_set(file_strings.into_values().collect())?;
                let filtered_utf16strings =
                    scoring_engine.filter_string_set(file_utf16strings.into_values().collect())?;
                let filtered_opcodes =
                    scoring_engine.filter_string_set(file_opcodes.into_values().collect())?;

                all_strings.insert(file_name.clone(), filtered_strings);
                all_utf16strings.insert(file_name.clone(), filtered_utf16strings);
                all_opcodes.insert(file_name.clone(), filtered_opcodes);
            }
            Err(e) => {
                if config.debug {
                    println!("[-] Error processing buffer {}: {}", i, e);
                }
            }
        }
    }

    Ok((file_infos, all_strings, all_opcodes, all_utf16strings))
}

pub fn process_buffers_with_stats(
    buffers: &Vec<Vec<u8>>,
    fp: PyRefMut<FileProcessor>,
) -> PyResult<ProcessingResults> {
    if buffers.is_empty() {
        return Ok(ProcessingResults::default());
    }

    let config = fp.config.clone();
    let max_file_size = config.max_file_size_mb * 1024 * 1024;

    // Process buffers in parallel
    let results: Vec<
        Result<(
            FileInfo,
            HashMap<String, TokenInfo>,
            HashMap<String, TokenInfo>,
            HashMap<String, TokenInfo>,
        )>,
    > = buffers
        .par_iter()
        .enumerate()
        .map(|(i, buffer)| {
            // Limit buffer size
            let limited_buffer = if buffer.len() > max_file_size {
                buffer[..max_file_size].to_vec()
            } else {
                buffer.clone()
            };

            process_buffer_u8(limited_buffer, &config)
                .map_err(|e| anyhow::anyhow!("Failed to process buffer {}: {}", i, e))
        })
        .collect();

    // Merge results
    let mut final_results = ProcessingResults::default();

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok((fi, mut strings, mut utf16strings, mut opcodes)) => {
                let file_name = format!("buffer_{}", i);

                // Check for SHA256 duplicates before adding
                if !final_results
                    .file_infos
                    .values()
                    .any(|existing_fi| existing_fi.sha256 == fi.sha256)
                {
                    final_results.file_infos.insert(file_name.clone(), fi);

                    // Add file reference to token infos
                    for (_, ti) in strings.iter_mut() {
                        ti.files.insert(file_name.clone());
                    }
                    for (_, ti) in utf16strings.iter_mut() {
                        ti.files.insert(file_name.clone());
                    }
                    for (_, ti) in opcodes.iter_mut() {
                        ti.files.insert(file_name.clone());
                    }

                    // Merge into final results
                    for (tok, info) in strings {
                        let entry = final_results.strings.entry(tok).or_default();
                        entry.merge(&info);
                    }

                    for (tok, info) in utf16strings {
                        let entry = final_results.utf16strings.entry(tok).or_default();
                        entry.merge(&info);
                    }

                    for (tok, info) in opcodes {
                        let entry = final_results.opcodes.entry(tok).or_default();
                        entry.merge(&info);
                    }
                }
            }
            Err(e) => {
                if config.debug {
                    println!("[-] Error processing buffer {}: {}", i, e);
                }
            }
        }
    }

    // Deduplicate strings (if needed)
    // Note: You might need to make deduplicate_strings available or implement it differently
    // For now, we'll skip deduplication since it requires mutable access to FileProcessor

    Ok(final_results)
}

// Add a new function that returns comprehensive analysis results
#[pyfunction]
pub fn analyze_buffers_comprehensive(
    buffers: Vec<Vec<u8>>,
    fp: PyRefMut<FileProcessor>,
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
    // First, process buffers to get aggregated stats
    let processing_results = process_buffers_with_stats(&buffers, fp)?;

    // Now analyze the results similar to process_malware
    let (string_combis, string_superrules, file_strings) = scoring_engine
        .sample_string_evaluation(processing_results.strings.clone())
        .unwrap();

    let (utf16_combis, utf16_superrules, file_utf16strings) = scoring_engine
        .sample_string_evaluation(processing_results.utf16strings.clone())
        .unwrap();

    let mut file_opcodes = HashMap::new();
    let opcode_combis = HashMap::new();
    let opcode_superrules = Vec::new();

    extract_stats_by_file(&processing_results.opcodes, &mut file_opcodes, None, None);

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
        processing_results.file_infos,
    ))
}

#[pyfunction]
pub fn process_malware(
    malware_path: String,
    mut fp: PyRefMut<FileProcessor>,
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
    //env_logger::init();
    // Check if we should disable super rules for single files
    env_logger::init_from_env("RUST_LOG");

    info!("Processing malware files...");
    let results = fp.parse_sample_dir(malware_path).unwrap();

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
    m.add_function(wrap_pyfunction!(process_buffer, m)?)?;
    m.add_function(wrap_pyfunction!(process_buffers_parallel, m)?)?;
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

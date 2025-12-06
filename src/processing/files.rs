use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path,
};

use crate::{
    Config, FileInfo, TokenInfo, TokenType, extract_and_count_ascii_strings,
    extract_and_count_utf16_strings, extract_opcodes, get_file_info,
};
use rayon::prelude::*;

use anyhow::{Context, Result};
use log::debug;
use pyo3::prelude::*;
use walkdir::WalkDir;

pub fn merge_stats(new: HashMap<String, TokenInfo>, stats: &mut HashMap<String, TokenInfo>) {
    for (tok, info) in new.into_iter() {
        if info.typ == TokenType::BINARY {
            //println!("{:?}", info);
        }
        if !stats.is_empty() {
            //println!("{:?}", &info);
            //assert_eq!(stats.iter().nth(0).unwrap().1.typ, info.typ);
        }
        let inf = stats.entry(tok).or_default();
        inf.merge(&info);
    }
}

#[pyclass]
#[derive(Debug, Clone, Default)]
pub struct FileProcessor {
    pub config: Config,

    pub strings: HashMap<String, TokenInfo>,
    pub utf16strings: HashMap<String, TokenInfo>,
    pub opcodes: HashMap<String, TokenInfo>,
    pub file_infos: HashMap<String, FileInfo>,
}

#[pyfunction]
pub fn get_files(folder: String, recursive: bool) -> PyResult<Vec<String>> {
    let mut files = Vec::new();

    if !recursive {
        if let Ok(entries) = fs::read_dir(folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Some(path_str) = path.to_str() {
                        files.push(path_str.to_string());
                    }
            }
        }
    } else {
        for entry in WalkDir::new(&folder).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file()
                && let Some(path_str) = entry.path().to_str() {
                    files.push(path_str.to_string());
                }
        }
    }

    Ok(files)
}

pub fn process_buffer_u8(
    buffer: Vec<u8>,
    config: &Config,
) -> Result<(
    FileInfo,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
)> {
    let fi: FileInfo = get_file_info(&buffer).unwrap();
    let (strings, utf16strings) = (
        extract_and_count_ascii_strings(&buffer, config.min_string_len, config.max_string_len),
        extract_and_count_utf16_strings(&buffer, config.min_string_len, config.max_string_len),
    );
    let mut opcodes = Default::default();
    if config.extract_opcodes {
        opcodes = extract_opcodes(buffer)?;
    }

    Ok((fi, strings, utf16strings, opcodes))
}

// Helper struct to hold results from parallel processing
#[pyclass]
#[derive(Default)]
pub struct ProcessingResults {
    pub file_infos: HashMap<String, FileInfo>,
    pub strings: HashMap<String, TokenInfo>,
    pub utf16strings: HashMap<String, TokenInfo>,
    pub opcodes: HashMap<String, TokenInfo>,
}

impl ProcessingResults {
    pub fn merge(&mut self, other: Self) {
        // Merge file infos (checking for duplicates)
        for (path, fi) in other.file_infos {
            // Check for SHA256 duplicates before inserting
            if !self
                .file_infos
                .values()
                .any(|existing_fi| existing_fi.sha256.eq(&fi.sha256))
            {
                self.file_infos.insert(path, fi);
                // Merge strings
                for (tok, info) in &other.strings {
                    let entry = self.strings.entry(tok.to_string()).or_default();
                    entry.merge(info);
                }

                // Merge UTF16 strings
                for (tok, info) in &other.utf16strings {
                    let entry = self.utf16strings.entry(tok.to_string()).or_default();
                    entry.merge(info);
                }

                // Merge opcodes
                for (tok, info) in &other.opcodes {
                    let entry = self.opcodes.entry(tok.to_string()).or_default();
                    entry.merge(info);
                }
            }
        }
    }
}

#[pymethods]
impl FileProcessor {
    #[new]
    #[pyo3(signature = (config = None))]
    pub fn new(config: Option<Config>) -> PyResult<Self> {
        let config = config.unwrap_or_default();
        config.validate()?;
        Ok(Self {
            config,
            ..Default::default()
        })
    }

    pub fn parse_sample_dir(&mut self, dir: String) -> PyResult<ProcessingResults> {
        // Get all files to process
        let files = get_files(dir, self.config.recursive)?;

        if self.config.debug {
            println!("[+] Processing {} files in parallel", files.len());
        }

        // Clone config for each thread (it's small, so this is fine)
        let config = self.config.clone();

        // Process files in parallel and collect results
        let results: Vec<Result<ProcessingResults>> = files
            .par_iter()
            .map(|file_path| process_file_with_checks_parallel(file_path, &config))
            .collect();

        // Merge all results
        let mut final_results = ProcessingResults::default();

        for result in results {
            match result {
                Ok(partial_results) => {
                    final_results.merge(partial_results);
                }
                Err(e) => {
                    if self.config.debug {
                        println!("[-] Error during processing: {}", e);
                    }
                }
            }
        }

        // Store results in self
        self.file_infos = final_results.file_infos;
        self.strings = final_results.strings;
        self.utf16strings = final_results.utf16strings;
        self.opcodes = final_results.opcodes;

        // Deduplicate strings
        self.deduplicate_strings();

        if self.config.debug {
            println!(
                "[+] Summary - Files: {} Strings: {} Utf16Strings: {} OpCodes: {}",
                self.file_infos.len(),
                self.strings.len(),
                self.utf16strings.len(),
                self.opcodes.len()
            );
        }

        Ok(ProcessingResults {
            strings: self.strings.clone(),
            opcodes: self.opcodes.clone(),
            utf16strings: self.utf16strings.clone(),
            file_infos: self.file_infos.clone(),
        })
    }

    pub fn clear_context(&mut self) {
        (
            self.strings,
            self.opcodes,
            self.utf16strings,
            self.file_infos,
        ) = Default::default();
    }

    pub fn process_file_with_checks(&mut self, file_path: String) -> bool {
        // This method is kept for backward compatibility but is now single-threaded
        // For parallel processing, use parse_sample_dir
        let os_path = path::Path::new(&file_path);

        if let Some(extensions) = &self.config.extensions
            && let Some(ext) = os_path.extension().and_then(OsStr::to_str)
                && !extensions
                    .iter()
                    .any(|x| x.eq(&ext.to_owned().to_lowercase()))
                {
                    debug!("[-] EXTENSION {} - Skipping file {}", ext, file_path);

                    return false;
                }
        let meta = fs::metadata(os_path).unwrap();
        if meta.len() < 15 {
            debug!("[-] File is empty - Skipping file {}", file_path);
            return false;
        }

        let (fi, strings, utf16strings, opcodes) =
            self.process_single_file(file_path.to_string()).unwrap();

        if self.file_infos.iter().any(|x| x.1.sha256 == fi.sha256) {
            if self.config.debug {
                println!(
                    "[-] Skipping strings/opcodes from {} due to SHA256 duplicate detection",
                    file_path
                );
            }
            return false;
        }
        self.file_infos.insert(file_path.to_string(), fi);
        merge_stats(strings, &mut self.strings);
        merge_stats(utf16strings, &mut self.utf16strings);
        merge_stats(opcodes, &mut self.opcodes);

        self.deduplicate_strings();

        if self.config.debug {
            println!(
                "[+] Processed {} Size: {} Strings: {} Utf16Strings: {} OpCodes: {}",
                file_path,
                meta.len(),
                self.strings.len(),
                self.utf16strings.len(),
                self.opcodes.len()
            );
        }
        true
    }

    pub fn deduplicate_strings(&mut self) {
        let utf16_keys: Vec<String> = self
            .utf16strings
            .keys()
            .filter(|k| self.strings.contains_key(*k))
            .cloned()
            .collect();
        for key in utf16_keys {
            if let Some(wide_info) = self.utf16strings.remove(&key)
                && let Some(ascii_info) = self.strings.get_mut(&key) {
                    ascii_info.count += wide_info.count;
                    ascii_info.also_wide = true;
                    ascii_info.files.extend(wide_info.files);
                }
        }

        if self.config.debug {
            println!("Deduplicating strings...");
        }

        // For the deduplication part, let's keep it simple and sequential
        // The performance impact is likely minimal compared to file processing
        let keys: Vec<String> = self.strings.keys().cloned().collect();

        // Group strings by length to optimize checks
        let mut strings_by_len: HashMap<usize, Vec<String>> = HashMap::new();
        for key in &keys {
            strings_by_len
                .entry(key.len())
                .or_default()
                .push(key.clone());
        }

        let mut to_remove = HashSet::new();

        // Only check strings that could contain each other (shorter strings can't contain longer ones)
        let mut sorted_lengths: Vec<usize> = strings_by_len.keys().cloned().collect();
        sorted_lengths.sort(); // Shortest to longest

        for (len_idx, &len) in sorted_lengths.iter().enumerate() {
            let current_strings = &strings_by_len[&len];

            // Check against all strings of this length or shorter
            for check_len in &sorted_lengths[..=len_idx] {
                let check_strings = &strings_by_len[check_len];

                for current in current_strings {
                    if to_remove.contains(current) {
                        continue;
                    }

                    for check in check_strings {
                        if current == check || to_remove.contains(check) {
                            continue;
                        }

                        if current.contains(check) {
                            // current contains check (check is shorter or equal length)
                            // Merge current into check
                            if let Some(current_info) = self.strings.remove(current)
                                && let Some(check_info) = self.strings.get_mut(check) {
                                    check_info.merge_existed(&current_info);
                                    to_remove.insert(current.clone());
                                    break;
                                }
                        }
                    }
                }
            }
        }

        // Strings were already removed during merging
    }

    fn process_single_file(
        &self,
        file_path: String,
    ) -> PyResult<(
        FileInfo,
        HashMap<String, TokenInfo>,
        HashMap<String, TokenInfo>,
        HashMap<String, TokenInfo>,
    )> {
        let (fi, strings, utf16strings, opcodes) = process_file_inner(&file_path, &self.config)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        Ok((fi, strings, utf16strings, opcodes))
    }

    // Core processing logic (shared between parallel and sequential versions)
}
// Helper method for parallel processing
fn process_file_with_checks_parallel(
    file_path: &str,
    config: &Config,
) -> Result<ProcessingResults> {
    let os_path = path::Path::new(file_path);

    // Check extension
    if let Some(extensions) = &config.extensions
        && let Some(ext) = os_path.extension().and_then(OsStr::to_str)
            && !extensions.contains(&ext.to_lowercase()) {
                if config.debug {
                    debug!("[-] EXTENSION {} - Skipping file {}", ext, file_path);
                }
                return Ok(ProcessingResults::default());
            }

    // Check file size
    let meta = fs::metadata(os_path)
        .with_context(|| format!("Failed to get metadata for: {}", file_path))?;
    if meta.len() < 15 {
        if config.debug {
            debug!("[-] File is empty - Skipping file {}", file_path);
        }
        return Ok(ProcessingResults::default());
    }

    // Process the file
    let (fi, strings, utf16strings, opcodes) = process_file_inner(file_path, config)?;

    let mut results = ProcessingResults {
        file_infos: HashMap::new(),
        strings,
        utf16strings,
        opcodes,
    };

    results.file_infos.insert(file_path.to_string(), fi);

    Ok(results)
}

fn process_file_inner(
    file_path: &str,
    config: &Config,
) -> Result<(
    FileInfo,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
)> {
    let file =
        File::open(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;

    let max_bytes = (config.max_file_size_mb * 1024 * 1024) as u64;
    let mut limited_reader = file.take(max_bytes);
    let mut buffer = Vec::new();
    limited_reader
        .read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read file: {}", file_path))?;

    let (fi, mut strings, mut utf16strings, mut opcodes) = process_buffer_u8(buffer, config)
        .with_context(|| format!("Failed to process file: {}", file_path))?;

    // Insert file reference into token infos
    for (_, ti) in strings.iter_mut() {
        ti.files.insert(file_path.to_string());
    }
    for (_, ti) in utf16strings.iter_mut() {
        ti.files.insert(file_path.to_string());
    }
    for (_, ti) in opcodes.iter_mut() {
        ti.files.insert(file_path.to_string());
    }

    Ok((fi, strings, utf16strings, opcodes))
}

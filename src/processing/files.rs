use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::{self, PathBuf},
};

use crate::{Config, FileInfo, TokenInfo, TokenType, extract_opcodes, get_file_info};
use rayon::prelude::*;

use anyhow::{Context, Result};
use log::debug;
use pyo3::prelude::*;
use walkdir::WalkDir;

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

pub fn get_files(folder: String, recursive: bool, max_file_count: usize) -> Result<Vec<String>> {
    let entries: Vec<PathBuf> = if !recursive {
        if let Ok(dir) = fs::read_dir(folder) {
            dir.flatten()
                .map(|x| x.path())
                .filter(|x| x.is_file())
                .collect()
        } else {
            Default::default()
        }
    } else {
        WalkDir::new(&folder)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|x| x.path().to_path_buf())
            .collect()
    };
    let entries: Vec<String> = entries
        .iter()
        .filter_map(|x| x.to_str())
        .take(max_file_count)
        .map(|x| x.to_string())
        .collect();
    println!("found {} files (max {})", entries.len(), max_file_count);
    Ok(entries)
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
#[derive(Default, Clone)]
pub struct ProcessingResults {
    #[pyo3(get, set)]
    pub file_infos: HashMap<String, FileInfo>,
    #[pyo3(get, set)]
    pub strings: HashMap<String, TokenInfo>,
    #[pyo3(get, set)]
    pub utf16strings: HashMap<String, TokenInfo>,
    #[pyo3(get, set)]
    pub opcodes: HashMap<String, TokenInfo>,
}

#[pymethods]
impl ProcessingResults {
    // In files.rs, add to ProcessingResults impl block

    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_file_count(&self) -> usize {
        self.file_infos.len()
    }

    pub fn get_string_count(&self) -> usize {
        self.strings.len()
    }

    pub fn get_utf16string_count(&self) -> usize {
        self.utf16strings.len()
    }

    pub fn get_opcode_count(&self) -> usize {
        self.opcodes.len()
    }

    pub fn deduplicate(&mut self) {
        // Simple deduplication implementation
        let mut strings_clone = self.strings.clone();

        // Remove ASCII strings that also exist as UTF16
        let utf16_keys: Vec<String> = self
            .utf16strings
            .keys()
            .filter(|k| strings_clone.contains_key(*k))
            .cloned()
            .collect();

        for key in utf16_keys {
            if let Some(wide_info) = self.utf16strings.remove(&key)
                && let Some(ascii_info) = strings_clone.get_mut(&key)
            {
                ascii_info.count += wide_info.count;
                ascii_info.also_wide = true;
                ascii_info.files.extend(wide_info.files);
            }
        }

        self.strings = strings_clone;
    }

    pub fn merge(&mut self, other: ProcessingResults) {
        // Merge file infos (checking for duplicates)
        for (path, fi) in other.file_infos.clone() {
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
        //println!("{:?}", config);
        let config = config.unwrap_or_default();
        //println!("{:?}", config);
        config.validate()?;
        Ok(Self {
            config,
            ..Default::default()
        })
    }

    pub fn parse_sample_dir(&mut self, dir: String) -> PyResult<ProcessingResults> {
        // Get all files to process
        //println!("{:?}", self.config);
        let files = get_files(dir, self.config.recursive, self.config.max_file_count).unwrap();

        if self.config.debug {
            println!("[+] Processing {} files in parallel", files.len());
        }

        // Clone config for each thread (it's small, so this is fine)
        let config = self.config.clone();

        // Process files in parallel and collect results
        let results: Vec<Result<ProcessingResults>> = files
            .par_iter()
            //.into_iter()
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
                && let Some(ascii_info) = self.strings.get_mut(&key)
            {
                ascii_info.count += wide_info.count;
                ascii_info.also_wide = true;
                ascii_info.files.extend(wide_info.files);
            }
        }

        return;
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
                                && let Some(check_info) = self.strings.get_mut(check)
                            {
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
    // Process the file
    if config.debug {
        println!("Processing file {}", file_path);
    }
    if let Some(extensions) = &config.extensions
        && let Some(ext) = os_path.extension().and_then(OsStr::to_str)
        && !extensions.contains(&ext.to_lowercase())
    {
        if config.debug {
            println!("[-] EXTENSION {} - Skipping file {}", ext, file_path);
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

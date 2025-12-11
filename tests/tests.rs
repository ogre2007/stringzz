#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use stringzz::{
        Config, FileInfo, FileProcessor, ProcessingResults, ScoringEngine, TokenInfo, TokenType,
        get_files, get_pe_info, is_ascii_string, is_base_64, is_hex_encoded, merge_stats,
        process_buffer_u8,
    };

    use tempfile::TempDir;

    #[test]
    fn test_extraction() {
        let test = "tests/fixtures/strings_test.bin";
        let mut fp = FileProcessor::default();

        fp.process_file_with_checks(test.to_owned());
        for _v in fp.strings.keys() {
            //println!("{:?}, {:?}, equals {}", v, "longer_string", v == "longer_string");
        }
        assert!(fp.strings.keys().any(|x| x.eq("longer_string")));
        assert!(fp.strings.keys().any(|x| x == "string_after_null"));
        assert!(fp.strings.keys().any(|x| x == "$SPECIAL_CHARS%^&*"));
        assert!(fp.strings.keys().any(|x| x == "user@example.com"));
        assert!(fp.strings.keys().any(|x| x == "path/to/file.txt"));
        assert!(
            fp.strings
                .keys()
                .any(|x| x == "very_long_string_that_exceeds_typical_minimum_length")
        );
        assert!(fp.strings.keys().any(|x| x == "short"));
        assert!(!fp.strings.keys().any(|x| x == "four"));
    }

    #[test]
    fn test_get_pe_info() {
        // Test with non-PE data
        let non_pe_data = b"Not a PE file";
        let mut fi: FileInfo = Default::default();

        let _ = get_pe_info(non_pe_data, &mut fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Test with small data (less than 0x40 bytes)
        let small_data = vec![0x4D, 0x5A]; // MZ header only
        let mut fi: FileInfo = Default::default();

        let _ = get_pe_info(&small_data, &mut fi);

        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Note: Testing with actual PE files would require real PE binaries
        // For unit tests, we mainly verify the error handling paths
    }

    #[test]
    fn test_is_ascii_string() {
        // Test with valid ASCII (no padding)
        let ascii_data = b"Hello World!";
        let result = is_ascii_string(ascii_data, false);
        assert!(result);

        // Test with valid ASCII (with padding allowed)
        let ascii_with_null = b"Hello\x00World";
        let result = is_ascii_string(ascii_with_null, true);
        assert!(result);

        // Test with non-ASCII (no padding)
        let non_ascii_data = b"Hello\xFFWorld";
        let result = is_ascii_string(non_ascii_data, false);
        assert!(!result);

        // Test with non-ASCII (with padding)
        let non_ascii_with_null = b"Hello\xFF\x00World";
        let result = is_ascii_string(non_ascii_with_null, true);
        assert!(!result);

        // Test with empty data
        let empty_data = b"";
        let result = is_ascii_string(empty_data, false);
        assert!(result);

        // Test with only null bytes (padding allowed)
        let null_data = &[0x00, 0x00, 0x00];
        let result = is_ascii_string(null_data, true);
        assert!(result);

        // Test with only null bytes (padding not allowed)
        let result = is_ascii_string(null_data, false);
        assert!(!result);
    }

    #[test]
    fn test_is_base_64() {
        // Valid base64 strings
        assert!(is_base_64("SGVsbG8=".to_string()).unwrap());
        assert!(!is_base_64("SGVsbG8".to_string()).unwrap());
        assert!(is_base_64("SGVsbG8h".to_string()).unwrap());
        assert!(is_base_64("U29tZSB0ZXh0".to_string()).unwrap());
        assert!(!is_base_64("".to_string()).unwrap()); // empty string is valid

        // Invalid base64 strings
        assert!(!is_base_64("SGVsbG8!".to_string()).unwrap()); // invalid character
        assert!(!is_base_64("SGVsbG8===".to_string()).unwrap()); // too many padding
        assert!(!is_base_64("SGVsbG".to_string()).unwrap()); // wrong length
        assert!(!is_base_64("SGVsbG===".to_string()).unwrap()); // wrong padding
        assert!(!is_base_64("ABC=DEF".to_string()).unwrap()); // padding in middle
    }

    #[test]
    fn test_get_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create test directory structure
        let dir1 = temp_dir.path().join("dir1");
        let dir2 = temp_dir.path().join("dir2");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();

        // Create test files
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = dir1.join("file2.txt");
        let file3 = dir2.join("file3.txt");

        File::create(&file1).unwrap();
        File::create(&file2).unwrap();
        File::create(&file3).unwrap();

        // Test non-recursive
        let files = get_files(temp_dir.path().to_str().unwrap().to_string(), false, 10000).unwrap();
        assert_eq!(files.len(), 1); // Only file1.txt in root
        assert!(files[0].contains("file1.txt"));

        // Test recursive
        let files = get_files(temp_dir.path().to_str().unwrap().to_string(), true, 10000).unwrap();
        assert_eq!(files.len(), 3); // All three files
        assert!(files.iter().any(|f| f.contains("file1.txt")));
        assert!(files.iter().any(|f| f.contains("file2.txt")));
        assert!(files.iter().any(|f| f.contains("file3.txt")));

        // Test with non-existent directory
        let files = get_files("/non/existent/directory".to_string(), true, 10000).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_is_hex_encoded() {
        // Valid hex strings with length check
        assert!(is_hex_encoded("48656C6C6F".to_string(), true).unwrap());
        assert!(is_hex_encoded("0123456789ABCDEF".to_string(), true).unwrap());
        assert!(is_hex_encoded("abcdef".to_string(), true).unwrap());
        assert!(!is_hex_encoded("".to_string(), true).unwrap()); // empty string

        // Invalid hex strings
        assert!(!is_hex_encoded("48656C6C6G".to_string(), true).unwrap()); // invalid character
        assert!(!is_hex_encoded("Hello".to_string(), true).unwrap()); // non-hex characters
        assert!(!is_hex_encoded("48 65 6C 6C 6F".to_string(), true).unwrap()); // spaces

        // Test with length check disabled
        assert!(is_hex_encoded("48656C6C6".to_string(), false).unwrap()); // odd length allowed
        assert!(is_hex_encoded("ABC".to_string(), false).unwrap()); // odd length allowed

        // Test with length check enabled for odd length
        assert!(!is_hex_encoded("48656C6C6".to_string(), true).unwrap()); // odd length not allowed
        assert!(!is_hex_encoded("ABC".to_string(), true).unwrap()); // odd length not allowed
    }

    #[test]
    fn test_calculate_imphash() {
        //todo!();
        // This is an internal function, but we can test it if we make it public
        // or use it indirectly through get_pe_info
        // For now, we'll test that get_pe_info doesn't panic on various inputs

        // Test with empty data
        let fi = &mut Default::default();
        let _ = get_pe_info(&[], fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Test with MZ header but invalid PE
        let mut mz_header = vec![0x4D, 0x5A]; // MZ
        mz_header.extend(vec![0u8; 60]); // padding to reach 0x3C
        mz_header.extend(vec![0x00, 0x00, 0x00, 0x00]); // e_lfanew = 0
        let fi = &mut Default::default();
        let _ = get_pe_info(&mz_header, fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());
    }

    use std::collections::{HashMap, HashSet};
    use std::io::Write;

    // Helper function to create test files with specific content
    fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
        let file_path = dir.path().join(name);
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content).unwrap();
        file_path.to_string_lossy().to_string()
    }

    #[test]
    fn test_get_files_non_recursive() {
        let temp_dir = TempDir::new().unwrap();

        // Create some test files
        create_test_file(&temp_dir, "file1.txt", b"Hello World");
        create_test_file(&temp_dir, "file2.txt", b"Test Content");

        // Create a subdirectory (should not be included in non-recursive)
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let sub_file = sub_dir.join("file3.txt");
        File::create(&sub_file).unwrap();

        let files = get_files(temp_dir.path().to_string_lossy().to_string(), false, 10000).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.contains("file1.txt")));
        assert!(files.iter().any(|f| f.contains("file2.txt")));
        assert!(!files.iter().any(|f| f.contains("file3.txt")));
    }

    #[test]
    fn test_get_files_recursive() {
        let temp_dir = TempDir::new().unwrap();

        // Create files at root
        create_test_file(&temp_dir, "file1.txt", b"Hello");

        // Create subdirectory with file
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let sub_file_path = sub_dir.join("file2.txt");
        File::create(&sub_file_path).unwrap();

        let files = get_files(temp_dir.path().to_string_lossy().to_string(), true, 10000).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.contains("file1.txt")));
        assert!(files.iter().any(|f| f.contains("file2.txt")));
    }

    #[test]
    fn test_process_buffer_u8() {
        let config = Config {
            min_string_len: 3,
            max_string_len: 100,
            extract_opcodes: false,
            ..Default::default()
        };

        // Create a simple executable-like buffer
        let buffer = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00HelloWorld\x00\x55\x8b\xec";

        let (fi, strings, _utf16strings, _opcodes) =
            process_buffer_u8(buffer.to_vec(), &config).unwrap();

        assert!(!fi.sha256.is_empty());
        assert!(strings.contains_key("HelloWorld"));
        //TODO
        //assert!(opcodes.len() > 0); // Should have extracted some opcodes
    }

    #[test]
    fn test_process_buffer_u8_no_opcodes() {
        let config = Config {
            min_string_len: 3,
            max_string_len: 100,
            extract_opcodes: false,
            ..Default::default()
        };

        let buffer = b"Test string content for extraction";

        let (_, strings, _utf16strings, _opcodes) =
            process_buffer_u8(buffer.to_vec(), &config).unwrap();

        assert!(strings.contains_key("Test string content for extraction"));
        //assert_eq!(opcodes.len(), 0); // Should not extract opcodes
    }

    #[test]
    fn test_file_processor_new() {
        let config = Config {
            min_string_len: 5,
            max_string_len: 50,
            debug: true,
            ..Default::default()
        };

        let processor = FileProcessor::new(Some(config.clone())).unwrap();

        assert_eq!(processor.config.min_string_len, 5);
        assert_eq!(processor.config.max_string_len, 50);
        assert!(processor.config.debug);
        assert!(processor.strings.is_empty());
        assert!(processor.opcodes.is_empty());
        assert!(processor.file_infos.is_empty());
    }

    #[test]
    fn test_file_processor_clear_context() {
        let mut processor = FileProcessor::new(None).unwrap();

        // Add some dummy data
        let token_info = TokenInfo {
            reprz: "test".to_string(),
            count: 1,
            files: HashSet::from(["file1.txt".to_string()]),
            typ: TokenType::ASCII,
            ..Default::default()
        };

        processor
            .strings
            .insert("test".to_string(), token_info.clone());
        processor
            .file_infos
            .insert("file1.txt".to_string(), FileInfo::default());

        assert!(!processor.strings.is_empty());
        assert!(!processor.file_infos.is_empty());

        processor.clear_context();

        assert!(processor.strings.is_empty());
        assert!(processor.file_infos.is_empty());
        assert!(processor.opcodes.is_empty());
        assert!(processor.utf16strings.is_empty());
    }

    #[test]
    fn test_process_file_with_checks_extension_filter() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.exe", b"MZ\x90\x00TestContent");

        let config = Config {
            extensions: Some(vec!["exe".to_string()]),
            debug: true,
            ..Default::default()
        };

        let mut processor = FileProcessor::new(Some(config)).unwrap();

        // Should process .exe file
        let result = processor.process_file_with_checks(file_path.clone());
        assert!(result);
        assert!(processor.file_infos.contains_key(&file_path));

        // Create a .txt file
        let txt_file = create_test_file(&temp_dir, "test.txt", b"Text content");

        // Reset processor
        processor.clear_context();
        processor.config.extensions = Some(vec!["exe".to_string()]);

        // Should skip .txt file
        let result = processor.process_file_with_checks(txt_file);
        assert!(!result);
        assert!(processor.file_infos.is_empty());
    }

    #[test]
    fn test_process_file_with_checks_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let empty_file = create_test_file(&temp_dir, "empty.exe", b"");

        let mut processor = FileProcessor::new(None).unwrap();

        // Should skip empty file
        let result = processor.process_file_with_checks(empty_file);
        assert!(!result);
        assert!(processor.file_infos.is_empty());
    }
    /*
       #[test]
       fn test_deduplicate_strings_basic() {
           let mut processor = FileProcessor::new(None).unwrap();

           // Create strings where one contains another
           let info1 = TokenInfo {
               reprz: "HelloWorld".to_string(),
               count: 2,
               files: HashSet::from(["file1.exe".to_string(), "file2.exe".to_string()]),
               typ: TokenType::ASCII,
               also_wide: false,
               ..Default::default()
           };

           let info2 = TokenInfo {
               reprz: "World".to_string(),
               count: 3,
               files: HashSet::from(["file3.exe".to_string()]),
               typ: TokenType::ASCII,
               also_wide: false,
               ..Default::default()
           };

           processor.strings.insert("HelloWorld".to_string(), info1);
           processor.strings.insert("World".to_string(), info2);

           processor.deduplicate_strings();

           // "World" should absorb "HelloWorld"
           assert!(!processor.strings.contains_key("HelloWorld"));
           assert!(processor.strings.contains_key("World"));

           let world_info = processor.strings.get("World").unwrap();
           assert_eq!(world_info.count, 5); // 2 + 3
           assert_eq!(world_info.files.len(), 3); // All 3 files
       }
    */
    #[test]
    fn test_deduplicate_strings_utf16_merge() {
        let mut processor = FileProcessor::new(None).unwrap();

        // Create ASCII string
        let ascii_info = TokenInfo {
            reprz: "Test".to_string(),
            count: 2,
            files: HashSet::from(["file1.exe".to_string()]),
            typ: TokenType::ASCII,
            also_wide: false,
            ..Default::default()
        };

        // Create UTF16 string with same content
        let utf16_info = TokenInfo {
            reprz: "Test".to_string(),
            count: 1,
            files: HashSet::from(["file2.exe".to_string()]),
            typ: TokenType::UTF16LE,
            also_wide: false,
            ..Default::default()
        };

        processor.strings.insert("Test".to_string(), ascii_info);
        processor
            .utf16strings
            .insert("Test".to_string(), utf16_info);

        processor.deduplicate_strings();

        // UTF16 string should be merged into ASCII string
        assert!(!processor.utf16strings.contains_key("Test"));
        assert!(processor.strings.contains_key("Test"));

        let test_info = processor.strings.get("Test").unwrap();
        assert_eq!(test_info.count, 3); // 2 + 1
        assert!(test_info.also_wide);
        assert_eq!(test_info.files.len(), 2);
    }

    #[test]
    fn test_parse_sample_dir_parallel() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple test files with different content
        let content1 = b"MZ\x90\x00\x03\x00UniqueString1\x00\x55\x8b\xec\x83\xec";
        let content2 = b"MZ\x90\x00\x03\x00UniqueString2\x00\x8b\x45\x08\x85\xc0";
        let content3 = b"MZ\x90\x00\x03\x00CommonString\x00\x55\x8b\xec\x83\xec";
        let content4 = b"MZ\x90\x00\x03\x00CommonString\x00\x8b\x45\x08\x85\xc0";

        create_test_file(&temp_dir, "file1.exe", content1);
        create_test_file(&temp_dir, "file2.exe", content2);
        create_test_file(&temp_dir, "file3.exe", content3);
        create_test_file(&temp_dir, "file4.exe", content4);

        let config = Config {
            min_string_len: 4,
            max_string_len: 100,
            extract_opcodes: false,
            debug: true,
            recursive: false,
            ..Default::default()
        };

        let mut processor = FileProcessor::new(Some(config)).unwrap();

        let results = processor
            .parse_sample_dir(temp_dir.path().to_string_lossy().to_string())
            .unwrap();

        // Should have processed 4 files
        assert_eq!(results.file_infos.len(), 4);

        // Should have extracted strings
        assert!(!results.strings.is_empty());

        // "CommonString" should appear in multiple files
        if let Some(common_string_info) = results.strings.get("CommonString") {
            assert!(common_string_info.count >= 2);
        }

        // Should have extracted opcodes
        //assert!(opcodes.len() > 0);
    }

    #[test]
    fn test_parse_sample_dir_duplicate_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create two files with identical content (same SHA256)
        let content = b"MZ\x90\x00\x03\x00TestContent\x00\x55\x8b\xec";

        let _file1 = create_test_file(&temp_dir, "file1.exe", content);
        let _file2 = create_test_file(&temp_dir, "file2.exe", content);

        let config = Config {
            debug: true,
            ..Default::default()
        };

        let mut processor = FileProcessor::new(Some(config)).unwrap();

        let file_infos = processor
            .parse_sample_dir(temp_dir.path().to_string_lossy().to_string())
            .unwrap()
            .file_infos;

        // Should only have one file info (duplicate detection)
        assert_eq!(file_infos.len(), 1);
    }

    #[test]
    fn test_parse_sample_dir_extension_filtering() {
        let temp_dir = TempDir::new().unwrap();

        // Create files with different extensions
        create_test_file(&temp_dir, "test.exe", b"MZ\x90\x00Executableawdwadaw");
        create_test_file(&temp_dir, "test.dll", b"MZ\x90\x00DLLdawdawddwadad");
        create_test_file(&temp_dir, "test.txt", b"Text fileadawdawdawdawdawdaw");

        let config = Config {
            extensions: Some(vec!["exe".to_string(), "dll".to_string()]),
            debug: true,
            recursive: false,
            ..Default::default()
        };

        let mut processor = FileProcessor::new(Some(config)).unwrap();

        let file_infos = processor
            .parse_sample_dir(temp_dir.path().to_string_lossy().to_string())
            .unwrap()
            .file_infos;

        // Should only have .exe and .dll files
        //assert_eq!(file_infos.len(), 2);
        println!("{:?}", file_infos);
        assert!(file_infos.keys().any(|k| k.ends_with(".exe")));
        assert!(file_infos.keys().any(|k| k.ends_with(".dll")));
        assert!(!file_infos.keys().any(|k| k.ends_with(".txt")));
    }

    #[test]
    fn test_merge_stats() {
        let mut stats = HashMap::new();

        let token_info1 = TokenInfo {
            reprz: "test".to_string(),
            count: 2,
            files: HashSet::from(["file1.exe".to_string()]),
            typ: TokenType::ASCII,
            also_wide: false,
            ..Default::default()
        };

        let mut new_stats = HashMap::new();
        let token_info2 = TokenInfo {
            reprz: "test".to_string(),
            count: 3,
            files: HashSet::from(["file2.exe".to_string()]),
            typ: TokenType::ASCII,
            also_wide: false,
            ..Default::default()
        };

        stats.insert("test".to_string(), token_info1);
        new_stats.insert("test".to_string(), token_info2);

        merge_stats(new_stats, &mut stats);

        let merged_info = stats.get("test").unwrap();
        assert_eq!(merged_info.count, 5); // 2 + 3
        assert_eq!(merged_info.files.len(), 2); // Both files
    }

    #[test]
    fn test_processing_results_merge() {
        let mut results1 = ProcessingResults::default();
        let mut results2 = ProcessingResults::default();

        // Add some data to results1
        let mut file_info1 = FileInfo::default();
        file_info1.sha256 = "hash1".to_string();
        results1
            .file_infos
            .insert("file1.exe".to_string(), file_info1);

        let token_info1 = TokenInfo {
            reprz: "string1".to_string(),
            count: 1,
            files: HashSet::from(["file1.exe".to_string()]),
            typ: TokenType::ASCII,
            also_wide: false,
            ..Default::default()
        };
        results1.strings.insert("string1".to_string(), token_info1);

        // Add some data to results2
        let mut file_info2 = FileInfo::default();
        file_info2.sha256 = "hash2".to_string();
        results2
            .file_infos
            .insert("file2.exe".to_string(), file_info2);

        let token_info2 = TokenInfo {
            reprz: "string1".to_string(),
            count: 2,
            files: HashSet::from(["file2.exe".to_string()]),
            typ: TokenType::ASCII,
            also_wide: false,
            ..Default::default()
        };
        results2.strings.insert("string1".to_string(), token_info2);

        // Merge results2 into results1
        results1.merge(results2);

        // Should have both files
        assert_eq!(results1.file_infos.len(), 2);

        // String should have merged counts
        let merged_string_info = results1.strings.get("string1").unwrap();
        assert_eq!(merged_string_info.count, 3); // 1 + 2
        assert_eq!(merged_string_info.files.len(), 2); // Both files
    }

    #[test]
    fn test_processing_results_merge_duplicate_sha256() {
        let mut results1 = ProcessingResults::default();
        let mut results2 = ProcessingResults::default();

        // Add file with specific SHA256 to results1
        let mut file_info1 = FileInfo::default();
        file_info1.sha256 = "same_hash".to_string();
        results1
            .file_infos
            .insert("file1.exe".to_string(), file_info1);

        // Add file with SAME SHA256 to results2 (duplicate)
        let mut file_info2 = FileInfo::default();
        file_info2.sha256 = "same_hash".to_string();
        results2
            .file_infos
            .insert("file2.exe".to_string(), file_info2);

        // Add a string from the duplicate file
        let token_info = TokenInfo {
            reprz: "test".to_string(),
            count: 1,
            files: HashSet::from(["file2.exe".to_string()]),
            typ: TokenType::ASCII,
            also_wide: false,
            ..Default::default()
        };
        results2.strings.insert("test".to_string(), token_info);

        // Merge - duplicate file should be skipped
        results1.merge(results2);

        // Should only have the first file (duplicate detection)
        assert_eq!(results1.file_infos.len(), 1);
        assert!(results1.file_infos.contains_key("file1.exe"));
        assert!(!results1.file_infos.contains_key("file2.exe"));

        // String from duplicate file should NOT be merged
        assert!(!results1.strings.contains_key("test"));
    }

    // Test for empty directory
    #[test]
    fn test_parse_sample_dir_empty() {
        let temp_dir = TempDir::new().unwrap();

        let mut processor = FileProcessor::new(None).unwrap();

        let results = processor
            .parse_sample_dir(temp_dir.path().to_string_lossy().to_string())
            .unwrap();

        assert!(results.strings.is_empty());
        assert!(results.opcodes.is_empty());
        assert!(results.utf16strings.is_empty());
        assert!(results.file_infos.is_empty());
    }

    // Test performance with many small files (parallel processing)
    #[test]
    fn test_parallel_performance() {
        let temp_dir = TempDir::new().unwrap();

        // Create 100 small test files
        for i in 0..100 {
            let content = format!("MZ\x70\x00TestFile{}Content\x00", i);
            create_test_file(&temp_dir, &format!("file{}.exe", i), content.as_bytes());
        }

        let config = Config {
            min_string_len: 4,
            max_string_len: 50,
            extract_opcodes: false, // Faster for test
            debug: false,
            recursive: false,
            ..Default::default()
        };

        let mut processor = FileProcessor::new(Some(config)).unwrap();

        // Time the parallel processing
        let start = std::time::Instant::now();
        let results = processor
            .parse_sample_dir(temp_dir.path().to_string_lossy().to_string())
            .unwrap();
        let duration = start.elapsed();

        println!("Parallel processing of 100 files took: {:?}", duration);

        // Should have processed all files
        assert_eq!(results.file_infos.len(), 100);
        assert!(results.strings.len() >= 100); // At least one string per file

        // The test should complete reasonably quickly
        // (This is more of a sanity check than a strict performance requirement)
        assert!(
            duration.as_secs() < 10,
            "Parallel processing took too long: {:?}",
            duration
        );
    }

    // Test mixed file sizes
    #[test]
    fn test_mixed_file_sizes() {
        let temp_dir = TempDir::new().unwrap();

        // Create files of different sizes
        create_test_file(&temp_dir, "small.exe", b"MZ\x90\x00Small\0aaaaaaaaaaa\0\0");
        create_test_file(&temp_dir, "medium.exe", &vec![b'A'; 1024 * 1024]); // 1MB
        create_test_file(&temp_dir, "large.exe", &vec![b'B'; 5 * 1024 * 1024]); // 5MB

        let config = Config {
            min_string_len: 5,
            max_file_size_mb: 10, // Allow all files
            debug: true,
            ..Default::default()
        };

        let mut processor = FileProcessor::new(Some(config)).unwrap();

        let results = processor
            .parse_sample_dir(temp_dir.path().to_string_lossy().to_string())
            .unwrap();
        assert_eq!(results.file_infos.len(), 3);
        assert!(results.strings.contains_key("Small"));
    }

    use pyo3::{Py, PyResult, Python};
    use stringzz::{analyze_buffers_comprehensive, process_buffers_with_stats};

    #[test]
    fn test_process_buffers_parallel() {
        pyo3::prepare_freethreaded_python();
        let config = Config {
            min_string_len: 3,
            max_string_len: 100,
            extract_opcodes: false,
            debug: false,
            ..Default::default()
        };

        let _ = Python::with_gil(|py| -> PyResult<_> {
            let py_fp: Py<FileProcessor> = Py::new(
                py,
                FileProcessor {
                    config,
                    ..Default::default()
                },
            )?;
            let py_scoring: Py<ScoringEngine> = Py::new(
                py,
                ScoringEngine {
                    good_strings_db: HashMap::new(),
                    good_opcodes_db: HashMap::new(),
                    good_imphashes_db: HashMap::new(),
                    good_exports_db: HashMap::new(),
                    pestudio_strings: HashMap::new(),
                    pestudio_marker: HashMap::new(),
                    base64strings: HashMap::new(),
                    hex_enc_strings: HashMap::new(),
                    reversed_strings: HashMap::new(),
                    excludegood: false,
                    min_score: 0,
                    superrule_overlap: 5,
                    string_scores: HashMap::new(),
                },
            )?;

            // Create test buffers
            let buffers = vec![
                b"MZ\x90\x00\x03\x00TestBuffer1\x00\x55\x8b\xec".to_vec(),
                b"MZ\x90\x00\x03\x00TestBuffer2\x00\x8b\x45\x08".to_vec(),
                b"MZ\x90\x00\x03\x00CommonString\x00\x55\x8b\xec".to_vec(),
                b"MZ\x90\x00\x03\x00CommonString\x00\x8b\x45\x08".to_vec(),
            ];
            let py_fp_ref = py_fp.borrow_mut(py);
            let py_scoring_ref = py_scoring.borrow_mut(py);
            let (
                string_combis,
                string_superrules,
                utf16_combis,
                utf16_superrules,
                opcode_combis,
                opcode_superrules,
                file_strings,
                file_opcodes,
                file_utf16strings,
                file_infos,
            ) = analyze_buffers_comprehensive(buffers, py_fp_ref, py_scoring_ref).unwrap();

            // Should have processed 4 buffers
            assert_eq!(file_infos.len(), 4);

            // Should have extracted strings
            assert!(file_strings.values().any(|v| !v.is_empty()));

            // Check that each buffer has its own entry
            assert!(file_infos.contains_key("buffer_0"));
            assert!(file_infos.contains_key("buffer_1"));
            assert!(file_infos.contains_key("buffer_2"));
            assert!(file_infos.contains_key("buffer_3"));
            Ok(())
        });
    }

    #[test]
    fn test_process_buffers_with_stats() {
        pyo3::prepare_freethreaded_python();
        let config = Config {
            min_string_len: 3,
            max_string_len: 100,
            extract_opcodes: false,
            debug: false,
            ..Default::default()
        };

        let _ = Python::with_gil(|py| -> PyResult<_> {
            let py_fp: Py<FileProcessor> = Py::new(
                py,
                FileProcessor {
                    config,
                    ..Default::default()
                },
            )?;

            let content = b"MZ\x90\x00\x03\x00DuplicateContent\x00\x55\x8b\xec";
            let buffers = vec![content.to_vec(), content.to_vec()];

            let py_fp_ref: pyo3::PyRefMut<'_, FileProcessor> = py_fp.borrow_mut(py);

            let results = process_buffers_with_stats(&buffers, py_fp_ref).unwrap();

            // Should only have one unique file (duplicate detection)
            assert_eq!(results.file_infos.len(), 1);

            // Should have extracted strings
            assert!(!results.strings.is_empty());

            // The string should appear twice (from both buffers)
            if let Some(token_info) = results.strings.get("DuplicateContent") {
                assert!(token_info.count >= 1);
            }
            Ok(())
        });
        // Create test buffers with duplicate content (same SHA256)
    }
}

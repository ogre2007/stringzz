use std::env;
use stringzz::{FileProcessor, TokenInfo};
fn main() {
    // Collect the arguments into a Vector of Strings
    let args: Vec<String> = env::args().collect();
    let mut fp = FileProcessor::default();
    fp.config.max_file_size_mb = 10;
    // The first argument (index 0) is always the program's executable path
    println!("Program path: {}", args[0]);

    // Iterate through the remaining arguments
    fp.config.recursive = true;
    fp.config.max_file_count = 10000;
    fp.config.debug = true;
    //if args.len() == 2 {
    println!("Additional arguments:");
    let _ = fp.parse_sample_dir("C:\\".to_string());
    let mut vec = fp
        .strings
        .clone()
        .into_iter()
        .collect::<Vec<(String, TokenInfo)>>();
    vec.sort_by_key(|x| x.1.count);
    for (_, ti) in vec {
        //println!("{}", ti.__str__());
    }
    for ti in fp.utf16strings.values() {
        println!("{}", ti.__str__());
    }
    println!(
        "[found {} strings and {} utf16 strings]",
        fp.strings.len(),
        fp.utf16strings.len()
    );
}

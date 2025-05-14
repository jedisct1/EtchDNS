use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Compile and run the corpus generator
    println!("cargo:rerun-if-changed=generate_corpus.rs");

    // Create corpus directories
    let targets = [
        "validate_dns_packet",
        "qname",
        "query_type_class",
        "is_dnssec_requested",
        "dns_key_from_packet",
    ];

    for target in &targets {
        let corpus_dir = format!("corpus/{}", target);
        if !Path::new(&corpus_dir).exists() {
            fs::create_dir_all(&corpus_dir).expect("Failed to create corpus directory");
        }
    }

    // Only compile and run the corpus generator if it doesn't exist yet
    // or if any of the corpus directories are empty
    let should_generate = targets.iter().any(|target| {
        let corpus_dir = format!("corpus/{}", target);
        let dir = Path::new(&corpus_dir);
        !dir.exists()
            || dir
                .read_dir()
                .map(|mut d| d.next().is_none())
                .unwrap_or(true)
    });

    if should_generate {
        let status = Command::new("rustc")
            .args(&[
                "--edition=2024",
                "generate_corpus.rs",
                "-o",
                "generate_corpus",
            ])
            .status()
            .expect("Failed to compile corpus generator");

        if !status.success() {
            panic!("Failed to compile corpus generator");
        }

        let status = Command::new("./generate_corpus")
            .status()
            .expect("Failed to run corpus generator");

        if !status.success() {
            panic!("Failed to generate corpus");
        }
    }
}

use std::path::PathBuf;

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut home = home::home_dir().expect("cannot determine home directory");
            home.push(".ssh");
            home.push("config");
            home
        });

    match ssh_config::parse_config_path(&config_path) {
        Ok(ssh_config) => match serde_json::to_string_pretty(&ssh_config) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("ssh-config: error serializing to JSON: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("ssh-config: error reading {:?}: {}", config_path, e);
            std::process::exit(1);
        }
    }
}

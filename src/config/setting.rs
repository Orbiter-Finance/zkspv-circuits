use lazy_static::lazy_static;
use serde::Deserialize;
use std::{fs::File, io::Read};

#[derive(Clone, Debug, Deserialize)]
pub struct SpvClientApi {
    pub host: String,
    pub port: isize,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DB {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Api {
    pub internal_host: String,
    pub internal_port: isize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rpcs {
    pub mainnet: String,
    pub goerli: String,

    pub arbitrum_mainnet: String,
    pub arbitrum_goerli: String,

    pub optimism_mainnet: String,
    pub optimism_goerli: String,

    pub zksync_mainnet: String,
    pub zksync_goerli: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub db: DB,
    pub api: Api,
    pub rpcs: Rpcs,
}

impl Default for Settings {
    fn default() -> Self {
        let file_path = "spv.toml";
        let mut file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) => panic!("no such file {} exception:{}", file_path, e),
        };
        let mut str_val = String::new();
        match file.read_to_string(&mut str_val) {
            Ok(s) => s,
            Err(e) => panic!("Error Reading file: {}", e),
        };
        toml::from_str(&str_val).expect("Parsing the configuration file failed")
    }
}

impl Settings {
    pub fn get<'a>() -> &'a Self {
        lazy_static! {
            static ref CACHE: Settings = Settings::default();
        }
        &CACHE
    }
}

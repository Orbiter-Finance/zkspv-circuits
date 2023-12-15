use jsonrpsee::core::Serialize;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(rename(deserialize = "list"))]
    pub list: Vec<String>,
}

impl CacheConfig {
    pub fn from_reader(path: &str) -> Self {
        let cache_file = File::open(path).unwrap();
        let data_reader = BufReader::new(cache_file);
        serde_json::from_reader(data_reader).unwrap()
    }
}

use crate::config::setting::Settings;

#[derive(Clone, Debug)]
pub struct Ethereum {
    pub mainnet: String,
    pub goerli: String,
}

#[derive(Clone, Debug)]
pub struct Arbitrum {
    pub mainnet: String,
    pub goerli: String,
}

#[derive(Clone, Debug)]
pub struct Optimism {
    pub mainnet: String,
    pub goerli: String,
}

#[derive(Clone, Debug)]
pub struct ZksyncEra {
    pub mainnet: String,
    pub goerli: String,
}

#[derive(Clone, Debug)]
pub struct RPCS {
    pub ethereum: Ethereum,
    pub arbitrum: Arbitrum,
    pub optimism: Optimism,
    pub zksync_era: ZksyncEra,
}

pub fn get_rpcs_config() -> RPCS {
    let setting = Settings::get();
    RPCS {
        ethereum: Ethereum {
            mainnet: setting.rpcs.mainnet.clone(),
            goerli: setting.rpcs.goerli.clone(),
        },
        arbitrum: Arbitrum {
            mainnet: setting.rpcs.arbitrum_mainnet.clone(),
            goerli: setting.rpcs.arbitrum_goerli.clone(),
        },
        optimism: Optimism {
            mainnet: setting.rpcs.optimism_mainnet.clone(),
            goerli: setting.rpcs.optimism_goerli.clone(),
        },
        zksync_era: ZksyncEra {
            mainnet: setting.rpcs.zksync_mainnet.clone(),
            goerli: setting.rpcs.zksync_goerli.clone(),
        },
    }
}

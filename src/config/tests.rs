use crate::config::contract::get_contract_config;
use crate::config::setting::Settings;
use crate::config::token::get_token_config;

#[test]
fn get_setting(){
    let setting = Settings::get();
    println!("{:?}", setting);
    let a = setting.internal_api.host.clone()+":"+ &*setting.internal_api.port.to_string();
    println!("{:?}", a);
}

#[test]
fn get_config(){
    let contract_config = get_contract_config();
    println!("contract_config:{:?}", contract_config);

    let token_config = get_token_config();
    println!("token_config:{:?}", token_config);
}


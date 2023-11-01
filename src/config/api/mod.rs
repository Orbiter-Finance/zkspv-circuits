use crate::config::setting::Settings;

pub fn get_internal_api() -> String {
    let setting = Settings::get();
    setting.api.internal_host.clone() + ":" + &*setting.api.internal_port.to_string()
}

pub fn get_spv_client_api() -> String {
    let setting = Settings::get();
    setting.api.spv_host.clone()
        + ":"
        + &*setting.api.spv_port.to_string()
        + "/"
        + &*setting.api.spv_path.clone()
}

use crate::config::setting::Settings;

pub fn get_internal_api() -> String {
    let setting = Settings::get();
    setting.api.internal_host.clone() + ":" + &*setting.api.internal_port.to_string()
}

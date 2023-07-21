use crate::config::setting::{ Settings};

pub fn get_internal_api() -> String {
    let setting = Settings::get();
    setting.internal_api.host.clone()+":"+ &*setting.internal_api.port.to_string()
}
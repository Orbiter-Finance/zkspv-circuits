use crate::config::setting::Settings;

pub fn get_rocks_db_path() -> String {
    let setting = Settings::get();
    setting.db.path.clone()
}

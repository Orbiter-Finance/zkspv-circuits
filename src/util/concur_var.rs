use std::{env::{set_var, var, VarError}, ffi::OsStr, thread};

// actually this is not thread safe yet, we should refactor the circuit framework first

pub fn set_var_thread_safe<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) {
    let thread_id: u64 = thread::current().id().as_u64().into();
    let new_key = key.as_ref().to_string_lossy().to_string() + &thread_id.to_string();
    // println!("set_var_thread_safe key: {:?} val: {:?}", new_key, value.as_ref().to_string_lossy().to_string());
    // set_var(new_key, value)
    set_var(key, value)
}


pub fn var_thread_safe<K: AsRef<OsStr>>(key: K) -> Result<String, VarError> {
    let thread_id: u64 = thread::current().id().as_u64().into();
    let new_key = key.as_ref().to_string_lossy().to_string() + &thread_id.to_string();
    // println!("var_thread_safe key: {:?}", new_key);
    // var(new_key)
    var(key)
}
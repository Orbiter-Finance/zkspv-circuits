#[derive(Debug)]
pub enum ErrorType {
    NetworkNotSupported,
}

pub const COMMIT_TRANSACTION_IS_EMPTY: &str =
    "CommitTransaction value cannot be empty in a specific network";

use std::borrow::ToOwned;

use ethers_core::abi::{Function, Param, ParamType, StateMutability, Token};
use ethers_core::types::Bytes;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum Erc20Error {
    /// Does not conform to the signature.
    #[error("does not conform to the signature")]
    SignatureNotConform,
}

pub fn get_erc20_transfer_abi() -> Function {
    Function {
        name: "transfer".to_owned(),
        inputs: vec![
            Param {
                name: "to".to_owned(),
                kind: ParamType::Address,
                internal_type: Some("address".to_owned()),
            },
            Param {
                name: "amount".to_owned(),
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".to_owned()),
            },
        ],
        outputs: vec![Param {
            name: "".to_owned(),
            kind: ParamType::Bool,
            internal_type: Some("bool".to_owned()),
        }],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    }
}

pub fn get_erc20_transfer_form_abi() -> Function {
    Function {
        name: "transferFrom".to_owned(),
        inputs: vec![
            Param {
                name: "from".to_owned(),
                kind: ParamType::Address,
                internal_type: Some("address".parse().unwrap()),
            },
            Param {
                name: "to".to_owned(),
                kind: ParamType::Address,
                internal_type: Some("address".parse().unwrap()),
            },
            Param {
                name: "amount".to_owned(),
                kind: ParamType::Uint(256),
                internal_type: Some("uint256".parse().unwrap()),
            },
        ],
        outputs: vec![Param {
            name: "".to_owned(),
            kind: ParamType::Bool,
            internal_type: Some("bool".parse().unwrap()),
        }],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    }
}

pub fn is_erc20_transaction(input: Bytes) -> bool {
    let transfer_signature = get_erc20_transfer_abi().short_signature().to_vec();
    let transfer_form_signature = get_erc20_transfer_form_abi().short_signature().to_vec();
    return if input.starts_with(&transfer_signature) || input.starts_with(&transfer_form_signature)
    {
        true
    } else {
        false
    };
}

pub fn decode_input(input: Bytes) -> Result<Vec<Token>, Erc20Error> {
    let transfer_signature = get_erc20_transfer_abi().short_signature().to_vec();
    let transfer_form_signature = get_erc20_transfer_form_abi().short_signature().to_vec();
    let token;
    if input.starts_with(&transfer_signature) {
        let no_signature = input.strip_prefix(transfer_signature.as_slice()).unwrap().to_vec();
        token = get_erc20_transfer_abi().decode_input(no_signature.as_slice()).unwrap();
    } else if input.starts_with(&transfer_form_signature) {
        let no_signature = input.strip_prefix(transfer_form_signature.as_slice()).unwrap().to_vec();
        token = get_erc20_transfer_form_abi().decode_input(no_signature.as_slice()).unwrap();
    } else {
        return Err(Erc20Error::SignatureNotConform);
    }
    Ok(token)
}

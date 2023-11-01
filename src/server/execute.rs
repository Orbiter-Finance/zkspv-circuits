use crate::arbitration::types::{
    EthereumDestProof, EthereumSourceProof, MerkleProof, ProofsRouter, RouterType,
};
use crate::server::OriginalProof;
use ethers_core::types::{Address, Bytes, H256};
use hex::FromHex;
use serde_json::Value;
use std::str::FromStr;

pub fn parse_original_proof(op: &OriginalProof) -> Option<ProofsRouter> {
    if op.chain_id == 5 {
        return if op.source {
            let proof = parse_ethereum_source_proof(op);
            Option::from(ProofsRouter {
                router_type: RouterType::GoerliSource,
                ethereum_source_proof: Option::from(proof),
                ethereum_dest_proof: None,
            })
        } else {
            let proof = parse_ethereum_dest_proof(op);
            Option::from(ProofsRouter {
                router_type: RouterType::GoerliDest,
                ethereum_source_proof: None,
                ethereum_dest_proof: Option::from(proof),
            })
        };
    }
    return None;
}

fn parse_ethereum_source_proof(op: &OriginalProof) -> EthereumSourceProof {
    let value: Value = serde_json::from_str(op.proof.as_str()).unwrap();
    let mut ethereum_proof =
        serde_json::from_str::<EthereumSourceProof>(op.proof.as_str()).unwrap();

    // Load transaction merkle proof
    {
        let mut transaction_merkle_proof_proof: Vec<Bytes> = vec![];
        let proofs = value["transactionProof"]["merkleProof"]["proof"].as_array().unwrap();
        for proof in proofs {
            let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
            transaction_merkle_proof_proof.push(Bytes::from(proof_bytes));
        }

        let transaction_merkle_proof = MerkleProof {
            key: Vec::from_hex(&value["transactionProof"]["merkleProof"]["key"].as_str().unwrap())
                .unwrap(),
            value: Vec::from_hex(
                &value["transactionProof"]["merkleProof"]["value"].as_str().unwrap(),
            )
            .unwrap(),
            proof: transaction_merkle_proof_proof,
            root: None,
        };

        ethereum_proof.transaction_proof.merkle_proof = transaction_merkle_proof;
    }

    // Load mdc pre rule merkle proof
    {
        let mut mdc_pre_rule_merkle_proof_proof: Vec<Bytes> = vec![];
        let proofs =
            value["mdcRuleProofs"]["mdcPreRule"]["merkleProof"]["proof"].as_array().unwrap();
        for proof in proofs {
            let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
            mdc_pre_rule_merkle_proof_proof.push(Bytes::from(proof_bytes));
        }

        let mdc_pre_rule_merkle_proof = MerkleProof {
            key: Vec::from_hex(
                &value["mdcRuleProofs"]["mdcPreRule"]["merkleProof"]["key"].as_str().unwrap(),
            )
            .unwrap(),
            value: Vec::from_hex(
                &value["mdcRuleProofs"]["mdcPreRule"]["merkleProof"]["value"].as_str().unwrap(),
            )
            .unwrap(),
            proof: mdc_pre_rule_merkle_proof_proof,
            root: Option::from(
                H256::from_str(
                    &value["mdcRuleProofs"]["mdcPreRule"]["merkleProof"]["root"].as_str().unwrap(),
                )
                .unwrap(),
            ),
        };

        ethereum_proof.mdc_rule_proofs.mdc_pre_rule.merkle_proof = mdc_pre_rule_merkle_proof;
    }

    // Load mdc current rule merkle proof
    {
        let mut mdc_current_rule_merkle_proof_proof: Vec<Bytes> = vec![];
        let proofs =
            value["mdcRuleProofs"]["mdcCurrentRule"]["merkleProof"]["proof"].as_array().unwrap();
        for proof in proofs {
            let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
            mdc_current_rule_merkle_proof_proof.push(Bytes::from(proof_bytes));
        }

        let mdc_current_rule_merkle_proof = MerkleProof {
            key: Vec::from_hex(
                &value["mdcRuleProofs"]["mdcCurrentRule"]["merkleProof"]["key"].as_str().unwrap(),
            )
            .unwrap(),
            value: Vec::from_hex(
                &value["mdcRuleProofs"]["mdcCurrentRule"]["merkleProof"]["value"].as_str().unwrap(),
            )
            .unwrap(),
            proof: mdc_current_rule_merkle_proof_proof,
            root: Option::from(
                H256::from_str(
                    &value["mdcRuleProofs"]["mdcCurrentRule"]["merkleProof"]["root"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
            ),
        };

        ethereum_proof.mdc_rule_proofs.mdc_current_rule.merkle_proof =
            mdc_current_rule_merkle_proof;
    }

    ethereum_proof
}

fn parse_ethereum_dest_proof(op: &OriginalProof) -> EthereumDestProof {
    let value: Value = serde_json::from_str(op.proof.as_str()).unwrap();
    let mut ethereum_proof = serde_json::from_str::<EthereumDestProof>(op.proof.as_str()).unwrap();

    // Load transaction merkle proof
    {
        let mut transaction_merkle_proof_proof: Vec<Bytes> = vec![];
        let proofs = value["transactionProof"]["merkleProof"]["proof"].as_array().unwrap();
        for proof in proofs {
            let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
            transaction_merkle_proof_proof.push(Bytes::from(proof_bytes));
        }

        let transaction_merkle_proof = MerkleProof {
            key: Vec::from_hex(&value["transactionProof"]["merkleProof"]["key"].as_str().unwrap())
                .unwrap(),
            value: Vec::from_hex(
                &value["transactionProof"]["merkleProof"]["value"].as_str().unwrap(),
            )
            .unwrap(),
            proof: transaction_merkle_proof_proof,
            root: None,
        };

        ethereum_proof.transaction_proof.merkle_proof = transaction_merkle_proof;
    }

    ethereum_proof
}

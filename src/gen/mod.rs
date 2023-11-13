use crate::*;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use itertools::Itertools;
use regex_simple::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::rc::Rc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployParamsJson {
    max_transcript_addr: u32,
    num_func_contracts: usize,
}
#[test]
fn test_sol() {
    let yul: String = fs::read_to_string("./data/arbitration/ethereum_source_final_1.yul")
        .unwrap()
        .parse()
        .unwrap();
    gen_sol_verifiers(yul);
}

pub fn gen_sol_verifiers(yul: String) {
    let sols_dir = "../axiom-v1-contracts/contracts/Verify";
    if PathBuf::new().join(sols_dir).exists() {
        fs::remove_dir_all(sols_dir).unwrap();
    }
    let sols_dir = &PathBuf::new().join(sols_dir);
    let max_line_size_per_file = 100 * 1000;
    let (sols, max_transcript_addr) =
        gen_evm_verifier_sols_from_yul(&yul, max_line_size_per_file).unwrap();
    {
        fs::create_dir_all(&sols_dir).unwrap();
        for (idx, sol) in sols.iter().enumerate() {
            let mut file =
                File::create(sols_dir.join(format!("VerifierLogicPart{}.sol", idx))).unwrap();
            file.write_all(sol.as_bytes()).unwrap();
        }
        let deploy_params =
            DeployParamsJson { max_transcript_addr, num_func_contracts: sols.len() };
        let mut json_file = File::create(sols_dir.join("deploy_params.json")).unwrap();
        json_file
            .write_all(serde_json::to_string_pretty(&deploy_params).unwrap().as_bytes())
            .unwrap();
    }
    let enter_verifier_sol = include_str!("Verifier.sol");
    fs::write(sols_dir.join("Verifier.sol"), enter_verifier_sol).unwrap();
    let mut verifier_router_sol = include_str!("VerifierRouter.sol").to_string();
    verifier_router_sol =
        verifier_router_sol.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
    fs::write(sols_dir.join("VerifierRouter.sol"), verifier_router_sol).unwrap();
    let mut verifier_logic_abstract_sol = include_str!("VerifierLogicAbstract.sol").to_string();
    verifier_logic_abstract_sol = verifier_logic_abstract_sol
        .replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
    fs::write(sols_dir.join("VerifierLogicAbstract.sol"), verifier_logic_abstract_sol).unwrap();
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L326-L602
pub fn gen_evm_verifier_sols_from_yul(
    yul: &str,
    max_line_size_per_file: usize,
) -> Result<(Vec<String>, u32), Box<dyn std::error::Error>> {
    // let file = File::open(input_file.clone())?;
    let reader = BufReader::new(yul.as_bytes());

    let mut transcript_addrs: Vec<u32> = Vec::new();

    // convert calldataload 0x0 to 0x40 to read from pubInputs, and the rest
    // from proof
    let calldata_pattern = Regex::new(r"^.*(calldataload\((0x[a-f0-9]+)\)).*$")?;
    let mstore_pattern = Regex::new(r"^\s*(mstore\(0x([0-9a-fA-F]+)+),.+\)")?;
    let mstore8_pattern = Regex::new(r"^\s*(mstore8\((\d+)+),.+\)")?;
    let mstoren_pattern = Regex::new(r"^\s*(mstore\((\d+)+),.+\)")?;
    let mload_pattern = Regex::new(r"(mload\((0x[0-9a-fA-F]+))\)")?;
    let keccak_pattern = Regex::new(r"(keccak256\((0x[0-9a-fA-F]+))")?;
    let modexp_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x5, (0x[0-9a-fA-F]+), 0xc0, (0x[0-9a-fA-F]+), 0x20)")?;
    let ecmul_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x7, (0x[0-9a-fA-F]+), 0x60, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecadd_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x6, (0x[0-9a-fA-F]+), 0x80, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecpairing_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x8, (0x[0-9a-fA-F]+), 0x180, (0x[0-9a-fA-F]+), 0x20)")?;
    let bool_pattern = Regex::new(r":bool")?;

    // Count the number of pub inputs
    let mut start = None;
    let mut end = None;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().starts_with("mstore(0x20") && start.is_none() {
            start = Some(i as u32);
        }

        if line.trim().starts_with("mstore(0x0") {
            end = Some(i as u32);
            break;
        }
    }

    let num_pubinputs = if let Some(s) = start { end.unwrap() - s } else { 0 };
    let mut max_pubinputs_addr = 0;
    if num_pubinputs > 0 {
        max_pubinputs_addr = num_pubinputs * 32 - 32;
    }

    let reader = BufReader::new(yul.as_bytes());
    let mut modified_lines: Vec<String> = Vec::new();

    for line in reader.lines() {
        let mut line = line?;
        let m = bool_pattern.captures(&line);
        if m.is_some() {
            line = line.replace(":bool", "");
        }

        let m = calldata_pattern.captures(&line);
        if let Some(m) = m {
            let calldata_and_addr = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;

            if addr_as_num <= max_pubinputs_addr {
                let pub_addr = format!("{:#x}", addr_as_num + 32);
                line = line
                    .replace(calldata_and_addr, &format!("mload(add(pubInputs, {}))", pub_addr));
            } else {
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                line =
                    line.replace(calldata_and_addr, &format!("mload(add(proof, {}))", proof_addr));
            }
        }

        let m = mstore8_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mstore, &format!("mstore8(add(transcript, {})", transcript_addr));
        }

        let m = mstoren_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mstore, &format!("mstore(add(transcript, {})", transcript_addr));
        }

        let m = modexp_pattern.captures(&line);
        if let Some(m) = m {
            let modexp = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            line = line.replace(
                modexp,
                &format!(
                    "staticcall(gas(), 0x5, add(transcript, {}), 0xc0, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecmul_pattern.captures(&line);
        if let Some(m) = m {
            let ecmul = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecmul,
                &format!(
                    "staticcall(gas(), 0x7, add(transcript, {}), 0x60, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecadd_pattern.captures(&line);
        if let Some(m) = m {
            let ecadd = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecadd,
                &format!(
                    "staticcall(gas(), 0x6, add(transcript, {}), 0x80, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecpairing_pattern.captures(&line);
        if let Some(m) = m {
            let ecpairing = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecpairing,
                &format!(
                    "staticcall(gas(), 0x8, add(transcript, {}), 0x180, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = mstore_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mstore, &format!("mstore(add(transcript, {})", transcript_addr));
        }

        let m = keccak_pattern.captures(&line);
        if let Some(m) = m {
            let keccak = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(keccak, &format!("keccak256(add(transcript, {})", transcript_addr));
        }

        // mload can show up multiple times per line
        loop {
            let m = mload_pattern.captures(&line);
            if m.is_none() {
                break;
            }
            let mload = m.as_ref().unwrap().get(1).unwrap().as_str();
            let addr = m.as_ref().unwrap().get(2).unwrap().as_str();

            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mload, &format!("mload(add(transcript, {})", transcript_addr));
        }

        modified_lines.push(line);
    }
    // modified_lines.push("}}".to_string());
    let mut outputs = vec![];
    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;

    let mut blocks = vec![];
    let mut is_nest = false;
    let mut cur_block = String::new();
    for line in modified_lines[16..modified_lines.len() - 7].iter() {
        if line.trim() == "{" {
            debug_assert!(!is_nest, "depth >= 2 is not supported");
            debug_assert_eq!(cur_block.len(), 0, "cur_block is not empty");
            is_nest = true;
            cur_block += line;
        } else if line.trim() == "}" {
            // debug_assert!(is_nest, "there is no opening brace");
            is_nest = false;
            cur_block += line;
            blocks.push(cur_block);
            cur_block = String::new();
        } else {
            if is_nest {
                cur_block += line;
            } else {
                blocks.push(line.to_string());
            }
        }
    }

    let mut codes = String::new();
    let mut func_idx = 0;
    let declares = r"
                    let f_p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    let f_q := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    function validate_ec_point(x, y) -> valid {
                        {
                            let x_lt_p := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let y_lt_p := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            valid := and(x_lt_p, y_lt_p)
                        }
                        {
                            let y_square := mulmod(y, y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let x_square := mulmod(x, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let x_cube := mulmod(x_square, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let x_cube_plus_3 := addmod(x_cube, 3, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let is_affine := eq(x_cube_plus_3, y_square)
                            valid := and(valid, is_affine)
                        }
                    }
    ";
    for block in blocks.iter() {
        let new_block = format!("{}\n", block);
        if codes.len() + new_block.len() > max_line_size_per_file {
            let mut template = include_str!("VerifierLogicPart.sol").to_string();
            template =
                template.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
            template = template.replace("<%ID%>", &format!("{}", func_idx));
            template = template.replace("<%ASSEMBLY%>", &codes);
            outputs.push(template);
            codes = declares.to_string();
            func_idx += 1;
        }
        codes += &new_block;
    }
    if codes.len() > 0 {
        let mut template = include_str!("VerifierLogicPart.sol").to_string();
        template = template.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
        template = template.replace("<%ID%>", &format!("{}", func_idx));
        template = template.replace("<%ASSEMBLY%>", &codes);
        outputs.push(template);
    }
    Ok((outputs, max_transcript_addr))
}

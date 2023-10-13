// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
//import "./IVerifier.sol";
import "./VerifierBase.sol";

// Mock Mdc contract
contract Verifier {
    address public verifierAddr;

    constructor(
        address _verifierAddr
    ) {
        verifierAddr = _verifierAddr;
    }

   function verify_call(
        bytes calldata instance,
        bytes calldata proof
    ) public view{
      VerifierBase verifier = VerifierBase(verifierAddr);
      require(verifier.verify(instances, proof), "invalid proof");
    }
}
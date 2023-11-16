// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierRouter.sol";

// Mock Mdc contract
contract Verifier {
    address public verifierRouterAddr;

    constructor(
        address _verifierRouterAddr
    ) {
        verifierRouterAddr = _verifierRouterAddr;
    }

   function verify(
           bytes calldata zkProof
       ) public view{
       uint256 instanceBytesLength = 2976;
          VerifierRouter verifier = VerifierRouter(verifierRouterAddr);
         require(verifier.verify(zkProof,instanceBytesLength), "invalid proof");
   }

}
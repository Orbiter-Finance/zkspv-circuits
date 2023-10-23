// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierRouter.sol";

// Mock Mdc contract
contract Verifier {
    address public verifierRouterAddr;
    uint256 constant SLOT_BITS = 32;

    constructor(
        address _verifierRouterAddr
    ) {
        verifierRouterAddr = _verifierRouterAddr;
    }

   function verify(
       uint256[] calldata instance,
        bytes calldata proof
    ) public view{
       VerifierRouter verifier = VerifierRouter(verifierRouterAddr);
      require(verifier.verify(instances, proof), "invalid proof");
    }

    function parse_instance(bytes calldata _instance) public pure returns(uint256[] memory)
    {
        uint256 length = _instance.length / SLOT_BITS;
        uint[] memory instance = new uint[](length);
        for (uint i = 0;i < length;i++){
            instance[i] = uint256(bytes32(_instance[SLOT_BITS * i:SLOT_BITS * (i + 1)]));
        }

        return instance;
    }

}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierFuncAbst.sol";

// MAX TRANSCRIPT ADDR: <%max_transcript_addr%>
contract VerifierBase {
    uint256 constant SIZE_LIMIT =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint numVerifierFuncs;
    address[] public verifierFuncs;
    uint public maxTranscriptAddr;

    bytes16 private constant _HEX_DIGITS = "0123456789abcdef";

    constructor(address[] memory _verifierFuncs, uint _maxTranscriptAddr) {
        numVerifierFuncs = _verifierFuncs.length;
        verifierFuncs = _verifierFuncs;
        maxTranscriptAddr = _maxTranscriptAddr;
    }

    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[<%max_transcript_addr%>] memory transcript;
        for (uint i = 0; i < pubInputs.length; i++) {
            require(
                pubInputs[i] < SIZE_LIMIT,
                string.concat(
                    "pubInputs[",
                    toString(i),
                    "] = ",
                    toString(pubInputs[i]),
                    " is too large"
                )
            );
        }
        VerifierFuncAbst verifier;
        for (uint i = 0; i < numVerifierFuncs; i++) {
            verifier = VerifierFuncAbst(verifierFuncs[i]);
            (success, transcript) = verifier
                .verifyPartial(pubInputs, proof, success, transcript);
        }
        return success;
    }

    // original: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Strings.sol#L24-L44
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            /// @solidity memory-safe-assembly
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _HEX_DIGITS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    // original: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol#L316C5-L352C6
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }
}
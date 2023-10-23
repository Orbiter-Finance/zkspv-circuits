// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierLogicAbstract.sol";

contract VerifierLogicPart<%ID%> is VerifierLogicAbstract {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes32[<%max_transcript_addr%>] memory transcript
    ) public view override returns (bool, bytes32[<%max_transcript_addr%>] memory) {
        assembly {{
            <%ASSEMBLY%>
        }}
        return (success, transcript);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./RollupState.sol";
import "./MerkleProofVerifier.sol";

contract Layer2Wrapper {
    RollupState public rollup;
    MerkleProofVerifier public verifier;

    constructor(address _rollup, address _verifier) {
        rollup = RollupState(_rollup);
        verifier = MerkleProofVerifier(_verifier);
    }

    function testRollup() public returns (uint256) {
        bytes memory batchData = new bytes(64);
        // Fill with some dummy data
        for (uint i = 0; i < 64; i++) {
            batchData[i] = bytes1(uint8(i));
        }
        bytes32 newRoot = keccak256("new_root");
        rollup.commitBatch(newRoot, batchData);
        return rollup.batchHeight(); // 1
    }

    function testMerkle() public view returns (bool) {
        bytes32 leaf = keccak256("leaf");
        bytes32 sibling = keccak256("sibling");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        
        bytes32 root;
        if (leaf <= sibling) {
            root = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            root = keccak256(abi.encodePacked(sibling, leaf));
        }

        return verifier.verify(proof, root, leaf); // true
    }
}

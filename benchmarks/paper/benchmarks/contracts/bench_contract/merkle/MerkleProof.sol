// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MerkleProof {
    uint256 constant FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant MIMC_ROUNDS = 91;

    function mimcHash(uint256 left, uint256 right) internal pure returns (uint256) {
        uint256 c = 0;
        uint256 x = left;
        for (uint256 i = 0; i < MIMC_ROUNDS; i++) {
            uint256 t = addmod(addmod(x, c, FIELD_PRIME), right, FIELD_PRIME);
            uint256 t2 = mulmod(t, t, FIELD_PRIME);
            uint256 t4 = mulmod(t2, t2, FIELD_PRIME);
            x = mulmod(mulmod(t4, t2, FIELD_PRIME), t, FIELD_PRIME);
            c = addmod(c, uint256(keccak256(abi.encodePacked(i))), FIELD_PRIME);
        }
        return addmod(x, right, FIELD_PRIME);
    }

    function verify(
        uint256[] memory proof,
        uint256 root,
        uint256 leaf,
        uint256[] memory positions
    ) internal pure returns (bool) {
        uint256 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (positions[i] == 0) {
                computedHash = mimcHash(computedHash, proof[i]);
            } else {
                computedHash = mimcHash(proof[i], computedHash);
            }
        }
        return computedHash == root;
    }

    function benchmark() public pure returns (bool) {
        uint256[] memory proof = new uint256[](8);
        uint256[] memory positions = new uint256[](8);
        uint256 leaf = 42;
        uint256 hash = leaf;
        for (uint256 i = 0; i < 8; i++) {
            proof[i] = i * 7 + 13;
            positions[i] = i % 2;
            hash = mimcHash(hash, proof[i]);
        }
        return verify(proof, hash, leaf, positions);
    }
}

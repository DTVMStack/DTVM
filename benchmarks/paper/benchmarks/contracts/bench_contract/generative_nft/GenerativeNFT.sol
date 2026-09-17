// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GenerativeNFT {
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant ROUNDS = 91;

    function mimcSponge(uint256 input, uint256 key) internal pure returns (uint256) {
        uint256 x = input;
        for (uint256 i = 0; i < ROUNDS; i++) {
            uint256 t = addmod(addmod(x, uint256(keccak256(abi.encodePacked(i))), P), key, P);
            uint256 t2 = mulmod(t, t, P);
            uint256 t4 = mulmod(t2, t2, P);
            x = mulmod(mulmod(t4, t2, P), t, P);
        }
        return addmod(x, key, P);
    }

    function generate(uint256 tokenId) public pure returns (uint256) {
        uint256 state = tokenId;

        // Generate 8 layers, each with its own MiMC sponge absorption
        for (uint256 layer = 0; layer < 8; layer++) {
            state = mimcSponge(state, layer + 1);
            uint256 attr = mimcSponge(state, layer + 100);
            state = addmod(state, attr, P);
        }

        return state;
    }
}

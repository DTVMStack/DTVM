// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./ERC721Enumerable.sol";
import "./OnChainMetadataNFT.sol";

contract NFTWrapper {
    ERC721Enumerable public enumNFT;
    OnChainMetadataNFT public metaNFT;

    constructor(address _enumNFT, address _metaNFT) {
        enumNFT = ERC721Enumerable(_enumNFT);
        metaNFT = OnChainMetadataNFT(_metaNFT);
    }

    function testEnumerableMintBurn() public returns (uint256) {
        enumNFT.mint(address(this), 1);
        enumNFT.mint(address(this), 2);
        enumNFT.burn(1);
        return enumNFT.totalSupply(); // should be 1
    }

    function testMetadata() public returns (string memory) {
        metaNFT.mint(address(this), 1, "TestNFT", "A test NFT");
        return metaNFT.tokenURI(1);
    }
}

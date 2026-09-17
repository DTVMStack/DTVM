// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyERC1155 is ERC1155, Ownable {
    // Token name
    string public name;
    // Token symbol
    string public symbol;

    constructor() ERC1155("https://game.example/api/item/{id}.json") Ownable(msg.sender) {
        name = "My Game Items";
        symbol = "TestGameSymbol";
    }

    // Mint function that only owner can call
    function mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public onlyOwner {
        _mint(account, id, amount, data);
    }

    // Batch mint function that only owner can call
    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public onlyOwner {
        _mintBatch(to, ids, amounts, data);
    }
}
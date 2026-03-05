// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PausableBurnableERC20 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    bool public paused;
    address public owner;

    constructor(uint256 _initialSupply) {
        owner = msg.sender;
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    modifier whenNotPaused() {
        require(!paused, "Pausable: paused");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function unpause() public onlyOwner {
        paused = false;
    }

    function transfer(address to, uint256 amount) public whenNotPaused returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: transfer amount exceeds balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function burn(uint256 amount) public whenNotPaused {
        require(balanceOf[msg.sender] >= amount, "ERC20: burn amount exceeds balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }
}

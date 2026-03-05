// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FeeOnTransferERC20 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public feePercentage; // e.g. 5 for 5%
    address public feeReceiver;

    constructor(uint256 _initialSupply, uint256 _feePercentage, address _feeReceiver) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
        feePercentage = _feePercentage;
        feeReceiver = _feeReceiver;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: transfer amount exceeds balance");
        
        uint256 fee = (amount * feePercentage) / 100;
        uint256 amountAfterFee = amount - fee;

        balanceOf[msg.sender] -= amount;
        balanceOf[feeReceiver] += fee;
        balanceOf[to] += amountAfterFee;

        return true;
    }
}

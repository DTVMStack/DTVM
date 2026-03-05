// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LendingPool {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    uint256 public totalDeposits;
    uint256 public totalBorrows;

    function deposit(address user, uint256 amount) public {
        deposits[user] += amount;
        totalDeposits += amount;
    }

    function borrow(address user, uint256 amount) public {
        require(deposits[user] * 2 >= borrows[user] + amount, "Insufficient collateral");
        borrows[user] += amount;
        totalBorrows += amount;
    }

    function repay(address user, uint256 amount) public {
        require(borrows[user] >= amount, "Repaying more than borrowed");
        borrows[user] -= amount;
        totalBorrows -= amount;
    }

    function getUtilization() public view returns (uint256) {
        if (totalDeposits == 0) return 0;
        return (totalBorrows * 100) / totalDeposits;
    }
}

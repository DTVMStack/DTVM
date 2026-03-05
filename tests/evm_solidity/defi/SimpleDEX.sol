// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleDEX {
    uint256 public reserveA;
    uint256 public reserveB;

    function init(uint256 _amountA, uint256 _amountB) public {
        require(reserveA == 0 && reserveB == 0, "Already initialized");
        reserveA = _amountA;
        reserveB = _amountB;
    }

    function swapAForB(uint256 amountAIn) public returns (uint256 amountBOut) {
        require(amountAIn > 0, "Invalid amount");
        
        uint256 amountInWithFee = amountAIn * 997;
        uint256 numerator = amountInWithFee * reserveB;
        uint256 denominator = (reserveA * 1000) + amountInWithFee;
        amountBOut = numerator / denominator;
        
        reserveA += amountAIn;
        reserveB -= amountBOut;
    }

    function swapBForA(uint256 amountBIn) public returns (uint256 amountAOut) {
        require(amountBIn > 0, "Invalid amount");
        
        uint256 amountInWithFee = amountBIn * 997;
        uint256 numerator = amountInWithFee * reserveA;
        uint256 denominator = (reserveB * 1000) + amountInWithFee;
        amountAOut = numerator / denominator;
        
        reserveB += amountBIn;
        reserveA -= amountAOut;
    }

    function getReserves() public view returns (uint256, uint256) {
        return (reserveA, reserveB);
    }
}

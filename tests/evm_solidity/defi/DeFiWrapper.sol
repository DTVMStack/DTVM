// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SimpleDEX.sol";
import "./LendingPool.sol";

contract DeFiWrapper {
    SimpleDEX public dex;
    LendingPool public pool;

    constructor(address _dex, address _pool) {
        dex = SimpleDEX(_dex);
        pool = LendingPool(_pool);
    }

    function testDexSwap() public returns (uint256) {
        dex.init(1000000, 1000000);
        return dex.swapAForB(1000); // expect 996
    }

    function testLending() public returns (uint256) {
        pool.deposit(address(this), 5000);
        pool.borrow(address(this), 2000);
        pool.repay(address(this), 1000);
        return pool.getUtilization(); // (1000 * 100) / 5000 = 20
    }
}

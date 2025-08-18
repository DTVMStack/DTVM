// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.0;

library FibonacciLib {
    event FibComputed(address indexed caller, uint256 n, uint256 result);

    function getFibonacci(uint256 n) internal returns (uint256) {
        uint256 a = 0;
        uint256 b = 1;
        uint256 MOD = 1000000007;
        for (uint i = 0; i < n; i++) {
            (a, b) = (b, (a % MOD + b % MOD) % MOD);
        }
        emit FibComputed(msg.sender, n, a);
        return a;
    }
}

contract TestFib {
    function fib(uint256 n) public returns (uint256) {
        return FibonacciLib.getFibonacci(n);
    }
}

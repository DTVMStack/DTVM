// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.0;

contract TestFib {
    uint256 private constant MOD = 1_000_000_007;

    event FibComputed(address indexed caller, uint256 n, uint256 result);

    function fib(uint256 n) public returns (uint256) {
        (uint256 result, ) = _fibDoubling(n);
        emit FibComputed(msg.sender, n, result);
        return result;
    }

    // Fast-doubling keeps recursion depth at O(log n) so even very large n stay within gas/stack limits.
    function _fibDoubling(uint256 n) internal pure returns (uint256, uint256) {
        if (n == 0) {
            return (0, 1);
        }

        (uint256 a, uint256 b) = _fibDoubling(n / 2);
        uint256 twoB = (2 * b) % MOD;
        uint256 sub = twoB >= a ? twoB - a : twoB + MOD - a;
        uint256 c = (a * sub) % MOD; // F(2k)
        uint256 d = (a * a % MOD + b * b % MOD) % MOD; // F(2k + 1)

        if (n % 2 == 0) {
            return (c, d);
        }
        return (d, (c + d) % MOD);
    }
}

// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.0;

contract uintTest {
	function testAddOverflow() public pure returns (bool) {
		uint64 uint64_max = type(uint64).max; // 2^64 - 1
		uint64 uint64_result = uint64_max + 1;
		require(uint64_result == 0, "uint64 overflow check failed");

		uint128 uint128_max = type(uint128).max; // 2^128 - 1
		uint128 uint128_result = uint128_max + 1;
		require(uint128_result == 0, "uint128 overflow check failed");

		uint192 uint192_max = type(uint192).max; // 2^192 - 1
		uint192 uint192_result = uint192_max + 1;
		require(uint192_result == 0, "uint192 overflow check failed");

		uint256 uint256_max = type(uint256).max; // 2^256 - 1
		uint256 uint256_result = uint256_max + 1;
		require(uint256_result == 0, "uint256 overflow check failed");

		return true;
	}
	function add() public pure returns (uint64) {
		uint64 uint64_max = type(uint64).max; // 2^64 - 1
		uint64 uint64_result = uint64_max + 1;
		return uint64_result;
	}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./PausableBurnableERC20.sol";
import "./FeeOnTransferERC20.sol";

contract ERC20BenchWrapper {
    PausableBurnableERC20 public pbToken;
    FeeOnTransferERC20 public fotToken;

    constructor(address _pbToken, address _fotToken) {
        pbToken = PausableBurnableERC20(_pbToken);
        fotToken = FeeOnTransferERC20(_fotToken);
    }

    function testPausableBurnable() public returns (uint256) {
        pbToken.transfer(address(0x123), 1000);
        pbToken.burn(500);
        return pbToken.totalSupply(); // 1000000 - 500 = 999500
    }

    function testFeeOnTransfer() public returns (uint256) {
        fotToken.transfer(address(0x456), 1000);
        // Fee is 5% of 1000 = 50. Receiver (this contract) gets 50.
        // address(0x456) gets 950.
        return fotToken.balanceOf(address(0x456)); // 950
    }
}

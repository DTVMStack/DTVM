// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.30;

contract CalleeContract {
    uint256 public x;

    function setX(uint256 _x) public {
        x = _x;
    }
    function getX() public view returns (uint256) {
        return x;
    }

    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }

    function incrementX() public {
        x += 1;
    }
}

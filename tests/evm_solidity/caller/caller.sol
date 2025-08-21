// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.30;

import "../callee/callee.sol";

contract CallerContract {
    CalleeContract public callee;

    constructor(address calleeAddress) {
        callee = CalleeContract(calleeAddress);
    }

    function setCalleeX(uint256 _x) external {
        callee.setX(_x);
    }

    function callAdd(uint256 a, uint256 b) external view returns (uint256) {
        return callee.add(a, b);
    }

    function callIncrementX() external {
        callee.incrementX();
    }

    function getCalleeX() external view returns (uint256) {
        return callee.getX();
    }
}

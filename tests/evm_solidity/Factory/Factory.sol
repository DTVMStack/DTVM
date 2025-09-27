// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.30;

contract Child {
    uint256 public value;

    constructor(uint256 v) {
        value = v;
    }
}

contract Factory {
    address public lastChild;

    event ChildDeployed(address child, uint256 value);

    function deployChild(uint256 v) public returns (address) {
        Child c = new Child(v);
        lastChild = address(c);
        emit ChildDeployed(lastChild, v);
        return lastChild;
    }
    function getLastChild() public view returns (uint256) {
        return Child(lastChild).value();
    }
}

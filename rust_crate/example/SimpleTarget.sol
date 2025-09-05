// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SimpleTarget
 * @dev A simple contract to be used as a call target
 */
contract SimpleTarget {
    uint256 public value;
    address public caller;
    
    event FunctionCalled(uint256 newValue, address sender);
    
    function setValue(uint256 _value) public returns (uint256) {
        value = _value;
        caller = msg.sender;
        emit FunctionCalled(_value, msg.sender);
        return _value;
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
    
    function revertWithMessage() public pure {
        revert("Target contract reverted");
    }
    
    function returnMultiple(uint256 a, uint256 b) public pure returns (uint256, uint256) {
        return (a + b, a * b);
    }
}
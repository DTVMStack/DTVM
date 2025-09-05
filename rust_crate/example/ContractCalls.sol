// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ContractCalls
 * @dev A contract to test various contract call operations
 */
contract ContractCalls {
    
    // Events to log call results
    event CallResult(string callType, bool success, bytes returnData);
    event ContractCreated2(address newContract, bool success);
    event ValueReceived(uint256 value, address sender);
    event ContractCreated(address newContract, uint256 value);
    
    // Storage for testing
    uint256 public storedValue;
    address public lastCaller;
    
    /**
     * @dev Simple function that can be called by others
     */
    function simpleFunction(uint256 value) public returns (uint256) {
        storedValue = value;
        lastCaller = msg.sender;
        emit ValueReceived(value, msg.sender);
        return value * 2;
    }
    
    /**
     * @dev Function that returns multiple values
     */
    function multipleReturns(uint256 a, uint256 b) public pure returns (uint256, uint256, uint256) {
        return (a + b, a * b, a > b ? a : b);
    }
    
    /**
     * @dev Function that reverts with a message
     */
    function revertFunction() public pure {
        revert("This function always reverts");
    }
    
    /**
     * @dev Test regular contract call (CALL)
     */
    function testCall(address target, bytes memory data) public payable returns (bool success, bytes memory returnData) {
        (success, returnData) = target.call{value: msg.value}(data);
        emit CallResult("CALL", success, returnData);
        return (success, returnData);
    }
    
    /**
     * @dev Test static call (STATICCALL)
     */
    function testStaticCall(address target, bytes memory data) public view returns (bool success, bytes memory returnData) {
        (success, returnData) = target.staticcall(data);
        return (success, returnData);
    }
    
    /**
     * @dev Test delegate call (DELEGATECALL)
     */
    function testDelegateCall(address target, bytes memory data) public returns (bool success, bytes memory returnData) {
        (success, returnData) = target.delegatecall(data);
        emit CallResult("DELEGATECALL", success, returnData);
        return (success, returnData);
    }

    /**
     * @dev Create a new SimpleContract
     */
    function createContract(uint256 _value) public returns (address) {
        SimpleContract newContract = new SimpleContract(_value);
        address contractAddress = address(newContract);
        
        emit ContractCreated(contractAddress, _value);
        
        return contractAddress;
    }
    
    /**
     * @dev Test contract creation with CREATE
     */
    function testCreate(uint256 _value) public returns (address newChildAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(SimpleContract).creationCode,
            abi.encode(_value)
        );
        
        assembly {
            newChildAddress := create(0, add(bytecode, 0x20), mload(bytecode))
            if eq(newChildAddress, 0) {
                revert(0, 0)
            }
        }
        
        bool success = newChildAddress != address(0);
        emit ContractCreated2(newChildAddress, success);
        return newChildAddress;
    }
    
    /**
     * @dev Test contract creation with CREATE2
     */
    function testCreate2(uint256 _value, bytes32 salt) public returns (address newContract) {
        bytes memory bytecode = abi.encodePacked(
            type(SimpleContract).creationCode,
            abi.encode(_value)
        );
        
        assembly {
            newContract := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if eq(newContract, 0) {
                revert(0, 0)
            }
        }
        
        bool success = newContract != address(0);
        emit ContractCreated2(newContract, success);
        return newContract;
    }
    
    /**
     * @dev Test multiple call types in sequence
     */
    function testMultipleCalls(address target) public returns (
        bool callSuccess,
        bool staticCallSuccess,
        bool delegateCallSuccess
    ) {
        // Prepare call data for simpleFunction(42)
        bytes memory data = abi.encodeWithSignature("simpleFunction(uint256)", 42);
        
        // Test regular call
        (callSuccess,) = target.call(data);
        emit CallResult("CALL", callSuccess, "");
        
        // Test static call (should work for view functions)
        bytes memory viewData = abi.encodeWithSignature("storedValue()");
        (staticCallSuccess,) = target.staticcall(viewData);
        emit CallResult("STATICCALL", staticCallSuccess, "");
        
        // Test delegate call
        (delegateCallSuccess,) = target.delegatecall(data);
        emit CallResult("DELEGATECALL", delegateCallSuccess, "");
        
        return (callSuccess, staticCallSuccess, delegateCallSuccess);
    }
    
    /**
     * @dev Test calling with different gas limits
     */
    function testCallWithGas(address target, bytes memory data, uint256 gasLimit) public returns (bool success, bytes memory returnData) {
        (success, returnData) = target.call{gas: gasLimit}(data);
        emit CallResult("CALL_WITH_GAS", success, returnData);
        return (success, returnData);
    }
    
    /**
     * @dev Test calling with value transfer
     */
    function testCallWithValue(address target, bytes memory data, uint256 value) public payable returns (bool success, bytes memory returnData) {
        require(msg.value >= value, "Insufficient value sent");
        (success, returnData) = target.call{value: value}(data);
        emit CallResult("CALL_WITH_VALUE", success, returnData);
        return (success, returnData);
    }
    
    /**
     * @dev Fallback function to receive calls
     */
    fallback() external payable {
        emit ValueReceived(msg.value, msg.sender);
    }
    
    /**
     * @dev Receive function for plain Ether transfers
     */
    receive() external payable {
        emit ValueReceived(msg.value, msg.sender);
    }
    
    /**
     * @dev Get contract's current state
     */
    function getState() public view returns (uint256 value, address caller, uint256 balance) {
        return (storedValue, lastCaller, address(this).balance);
    }
}

/**
 * @title SimpleContract
 * @dev A simple contract that can be created by the factory
 */
contract SimpleContract {
    uint256 public value;
    address public creator;
    
    event ValueSet(uint256 newValue);
    
    constructor(uint256 _value) {
        value = _value;
        creator = msg.sender;
        emit ValueSet(_value);
    }
    
    function setValue(uint256 _newValue) public {
        value = _newValue;
        emit ValueSet(_newValue);
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
}

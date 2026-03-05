// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultiSigWallet {
    event Deposit(address indexed sender, uint256 amount, uint256 balance);
    event SubmitTransaction(address indexed owner, uint256 indexed txIndex, address indexed to, uint256 value, bytes data);
    event ConfirmTransaction(address indexed owner, uint256 indexed txIndex);
    event RevokeConfirmation(address indexed owner, uint256 indexed txIndex);
    event ExecuteTransaction(address indexed owner, uint256 indexed txIndex);

    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public numConfirmationsRequired;

    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 numConfirmations;
    }

    mapping(uint256 => mapping(address => bool)) public isConfirmed;
    Transaction[] public transactions;

    constructor(address owner1, address owner2, uint256 _numConfirmationsRequired) {
        require(owner1 != address(0) && owner2 != address(0), "invalid owner");
        require(_numConfirmationsRequired > 0 && _numConfirmationsRequired <= 2, "invalid number of required confirmations");

        isOwner[owner1] = true;
        isOwner[owner2] = true;
        owners.push(owner1);
        owners.push(owner2);

        numConfirmationsRequired = _numConfirmationsRequired;
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    function submitTransaction(address _to, uint256 _value, bytes memory _data) public returns (uint256) {
        require(isOwner[msg.sender], "not owner");
        uint256 txIndex = transactions.length;

        transactions.push(Transaction({
            to: _to,
            value: _value,
            data: _data,
            executed: false,
            numConfirmations: 0
        }));

        emit SubmitTransaction(msg.sender, txIndex, _to, _value, _data);
        return txIndex;
    }

    function confirmTransaction(uint256 _txIndex) public {
        require(isOwner[msg.sender], "not owner");
        require(_txIndex < transactions.length, "tx does not exist");
        require(!transactions[_txIndex].executed, "tx already executed");
        require(!isConfirmed[_txIndex][msg.sender], "tx already confirmed");

        Transaction storage transaction = transactions[_txIndex];
        transaction.numConfirmations += 1;
        isConfirmed[_txIndex][msg.sender] = true;

        emit ConfirmTransaction(msg.sender, _txIndex);
    }

    function executeTransaction(uint256 _txIndex) public returns (bool) {
        require(isOwner[msg.sender], "not owner");
        require(_txIndex < transactions.length, "tx does not exist");
        require(!transactions[_txIndex].executed, "tx already executed");
        require(transactions[_txIndex].numConfirmations >= numConfirmationsRequired, "cannot execute tx");

        Transaction storage transaction = transactions[_txIndex];
        transaction.executed = true;

        // Simulate execution
        // (bool success, ) = transaction.to.call{value: transaction.value}(transaction.data);
        // require(success, "tx failed");

        emit ExecuteTransaction(msg.sender, _txIndex);
        return true;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RollupState {
    bytes32 public stateRoot;
    uint256 public batchHeight;

    event StateBatchCommitted(uint256 indexed batchIndex, bytes32 stateRoot);

    function commitBatch(bytes32 _newStateRoot, bytes calldata _batchData) public {
        require(_batchData.length > 0, "Empty batch");
        
        // Simulate processing batch data
        uint256 txCount = _batchData.length / 32;
        bytes32 computedRoot = stateRoot;
        
        for (uint256 i = 0; i < txCount; i++) {
            bytes32 txHash;
            assembly {
                txHash := calldataload(add(_batchData.offset, mul(i, 32)))
            }
            computedRoot = keccak256(abi.encodePacked(computedRoot, txHash));
        }

        stateRoot = _newStateRoot;
        batchHeight++;
        emit StateBatchCommitted(batchHeight, stateRoot);
    }
}

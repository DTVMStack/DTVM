// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title BaseHostFunctions
 * @dev A simple contract to test EVM host functions and blockchain information
 */
contract BaseHostFunctions {
    // Events to log the retrieved information
    event AddressInfo(address contractAddress);
    event ChainInfo(uint256 chainId);

    /**
     * @dev Get contract address information
     */
    function getAddressInfo() public returns (address) {
        address contractAddr = address(this);
        emit AddressInfo(contractAddr);
        return contractAddr;
    }

    /**
     * @dev Get block information
     */
    function getBlockNum() public view returns (uint256) {
        return block.number;
    }

    function getTimestamp() public view returns (uint256) {
        return block.timestamp;
    }

    function getGasLimit() public view returns (uint256) {
        return block.gaslimit;
    }

    function getCoinbase() public view returns (address) {
        return block.coinbase;
    }

    /**
     * @dev Get transaction information
     */
    function getOrigin() public view returns (address) {
        return tx.origin;
    }

    function getGasprice() public view returns (uint256) {
        return tx.gasprice;
    }

    function getGasleft() public view returns (uint256) {
        return gasleft();
    }

    /**
     * @dev Get chain ID
     */
    function getChainInfo() public returns (uint256) {
        uint256 chainId = block.chainid;
        emit ChainInfo(chainId);
        return chainId;
    }

    /**
     * @dev Get fee information
     */
    function getBaseFee() public view returns (uint256) {
        return block.basefee;
    }

    function getBlobBaseFee() public view returns (uint256) {
        return block.blobbasefee;
    }

    /**
     * @dev Get hash information
     */
    function getblockHash(uint256 blockNumber) public view returns (bytes32) {
        return blockhash(blockNumber);
    }

    function getPrevRandao() public view returns (bytes32) {
        return bytes32(block.prevrandao);
    }

    /**
     * @dev Test SHA256 hash function
     */
    function testSha256(bytes memory data) public pure returns (bytes32) {
        return sha256(data);
    }
}

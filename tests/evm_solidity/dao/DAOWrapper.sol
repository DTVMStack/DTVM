// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SimpleGovernor.sol";
import "./MultiSigWallet.sol";

contract DAOWrapper {
    SimpleGovernor public governor;
    MultiSigWallet public wallet;

    constructor(address _governor, address payable _wallet) {
        governor = SimpleGovernor(_governor);
        wallet = MultiSigWallet(_wallet);
    }

    function testGovernor() public returns (bool) {
        uint256 pid = governor.propose("Upgrade system");
        governor.vote(pid, true);
        return governor.execute(pid);
    }

    function testMultiSig() public returns (bool) {
        uint256 txId = wallet.submitTransaction(address(0x456), 0, "0x");
        wallet.confirmTransaction(txId);
        return wallet.executeTransaction(txId);
    }
}

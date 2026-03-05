// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleGovernor {
    struct Proposal {
        uint256 id;
        address proposer;
        string description;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    function propose(string memory description) public returns (uint256) {
        proposalCount++;
        Proposal storage p = proposals[proposalCount];
        p.id = proposalCount;
        p.proposer = msg.sender;
        p.description = description;
        return proposalCount;
    }

    function vote(uint256 proposalId, bool support) public {
        Proposal storage p = proposals[proposalId];
        require(p.id != 0, "Proposal does not exist");
        require(!p.hasVoted[msg.sender], "Already voted");
        require(!p.executed, "Already executed");

        p.hasVoted[msg.sender] = true;
        if (support) {
            p.forVotes++;
        } else {
            p.againstVotes++;
        }
    }

    function execute(uint256 proposalId) public returns (bool) {
        Proposal storage p = proposals[proposalId];
        require(p.id != 0, "Proposal does not exist");
        require(!p.executed, "Already executed");
        require(p.forVotes > p.againstVotes, "Proposal failed");

        p.executed = true;
        return true;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleToken {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) private allowances;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed to, uint256 value);

    constructor(uint256 _totalSupply) {
        name = "SimpleToken";
        symbol = "STK";
        decimals = 18;
        totalSupply = _totalSupply;
        if (_totalSupply > 0) {
            balances[msg.sender] = _totalSupply;
            emit Transfer(address(0), msg.sender, _totalSupply);
        }
    }

    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }

    function mint(address to, uint256 amount) public {
        require(to != address(0), "Invalid recipient address");

        totalSupply += amount;
        balances[to] += amount;

        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    function transfer(address recipient, uint256 amount) public returns (bool) {
        require(recipient != address(0), "Invalid recipient address");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[recipient] += amount;

        emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public returns (bool) {
        require(recipient != address(0), "Invalid recipient address");
        require(balances[sender] >= amount, "Insufficient balance");
        require(allowances[sender][msg.sender] >= amount, "Insufficient allowance");

        balances[sender] -= amount;
        balances[recipient] += amount;
        allowances[sender][msg.sender] -= amount;

        emit Transfer(sender, recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return allowances[owner][spender];
    }
}

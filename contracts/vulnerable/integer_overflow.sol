// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24; // Vulnerable to integer overflow

/**
 * @title IntegerOverflowVictim
 * @dev Example contract vulnerable to integer overflow/underflow
 * Vulnerability: SWC-101 - Integer Overflow and Underflow
 */
contract IntegerOverflowVictim {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    function mint(address to, uint256 amount) external {
        // VULNERABLE: No overflow check
        balances[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: No overflow/underflow checks
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function batchTransfer(address[] recipients, uint256 amount) external returns (bool) {
        uint256 length = recipients.length;
        
        // VULNERABLE: Multiplication overflow
        uint256 totalAmount = length * amount;
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");
        
        balances[msg.sender] -= totalAmount;
        
        for (uint256 i = 0; i < length; i++) {
            balances[recipients[i]] += amount;
            emit Transfer(msg.sender, recipients[i], amount);
        }
        
        return true;
    }
}
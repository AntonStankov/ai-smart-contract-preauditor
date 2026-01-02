// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyVictim
 * @dev Example contract vulnerable to reentrancy attacks
 * Vulnerability: SWC-107 - State changes after external calls
 */
contract ReentrancyVictim {
    mapping(address => uint256) public userBalances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    function deposit() external payable {
        userBalances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external {
        require(userBalances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State change after external call - allows reentrancy
        userBalances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }
    
    function getBalance(address user) external view returns (uint256) {
        return userBalances[user];
    }
}
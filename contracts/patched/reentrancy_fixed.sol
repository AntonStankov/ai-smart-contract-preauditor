// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyFixed
 * @dev Fixed version implementing checks-effects-interactions pattern
 * Fix for: SWC-107 - Reentrancy vulnerability
 */
contract ReentrancyFixed {
    mapping(address => uint256) public userBalances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    function deposit() external payable {
        userBalances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external {
        require(userBalances[msg.sender] >= amount, "Insufficient balance");
        
        // FIXED: State change before external call (checks-effects-interactions)
        userBalances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
        
        // External call after state change - prevents reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) {
            // Revert state change on failed transfer
            userBalances[msg.sender] += amount;
            revert("Transfer failed");
        }
    }
    
    function getBalance(address user) external view returns (uint256) {
        return userBalances[user];
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControlVictim
 * @dev Example contract with access control vulnerabilities
 * Vulnerabilities: SWC-105 - Unprotected Ether Withdrawal, tx.origin usage
 */
contract AccessControlVictim {
    address public owner;
    mapping(address => uint256) public deposits;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // VULNERABLE: Uses tx.origin instead of msg.sender
    function withdrawAll() external {
        require(tx.origin == owner, "Only owner can withdraw");
        
        uint256 contractBalance = address(this).balance;
        (bool success, ) = tx.origin.call{value: contractBalance}("");
        require(success, "Withdrawal failed");
        
        emit Withdrawal(tx.origin, contractBalance);
    }
    
    // VULNERABLE: No access control on critical function
    function emergencyWithdraw() external {
        uint256 contractBalance = address(this).balance;
        (bool success, ) = msg.sender.call{value: contractBalance}("");
        require(success, "Emergency withdrawal failed");
    }
    
    // VULNERABLE: Allows arbitrary address to become owner
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner can transfer");
        owner = newOwner;
    }
    
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
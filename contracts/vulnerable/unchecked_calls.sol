// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UncheckedCallVictim  
 * @dev Example contract with unchecked external calls
 * Vulnerability: SWC-104 - Unchecked Return Value For Low Level Calls
 */
contract UncheckedCallVictim {
    mapping(address => uint256) public balances;
    address[] public recipients;
    
    event Deposit(address indexed user, uint256 amount);
    event BatchTransfer(uint256 totalAmount);
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function addRecipient(address recipient) external {
        recipients.push(recipient);
    }
    
    // VULNERABLE: Unchecked external calls can fail silently
    function distributeFunds() external {
        require(recipients.length > 0, "No recipients");
        uint256 amountPerRecipient = address(this).balance / recipients.length;
        
        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABLE: Call return value not checked
            recipients[i].call{value: amountPerRecipient}("");
        }
        
        emit BatchTransfer(address(this).balance);
    }
    
    // VULNERABLE: Delegatecall to arbitrary address
    function executeArbitraryCall(address target, bytes calldata data) external returns (bool) {
        // VULNERABLE: No validation of target or data
        (bool success, ) = target.delegatecall(data);
        return success; // Return value ignored by caller in typical usage
    }
    
    // VULNERABLE: External call in loop without gas limit consideration
    function notifyRecipients(bytes memory data) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABLE: Could run out of gas or fail silently
            recipients[i].call(data);
        }
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    mapping(address => uint256) public balances;
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // Vulnerable to reentrancy - state change after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;  // State change after external call
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
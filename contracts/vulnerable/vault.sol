// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Vault {
    IERC20 public immutable token;

    mapping(address => uint256) private balances;
    uint256 public totalDeposits;

    constructor(IERC20 _token) {
        token = _token;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero amount");
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient");

        _beforeWithdraw(msg.sender, amount);

        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    function _beforeWithdraw(address user, uint256 amount) internal {
        require(token.transfer(user, amount), "transfer failed");
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}

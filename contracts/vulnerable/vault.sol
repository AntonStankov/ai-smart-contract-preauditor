// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract RewardDistributor {
    IERC20 public immutable rewardToken;
    address public owner;

    mapping(address => uint256) public rewards;
    address[] private participants;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(IERC20 _rewardToken) {
        rewardToken = _rewardToken;
        owner = msg.sender;
    }

    function register(address user, uint256 reward) external onlyOwner {
        if (rewards[user] == 0) {
            participants.push(user);
        }
        rewards[user] += reward;
    }

    function distribute() external onlyOwner {
        uint256 balance = rewardToken.balanceOf(address(this));

        for (uint256 i = 0; i < participants.length; i++) {
            address user = participants[i];
            uint256 amount = rewards[user];

            if (amount == 0) continue;
            if (balance < amount) break;

            rewards[user] = 0;
            rewardToken.transfer(user, amount);

            balance -= amount;
        }
    }

    function participantCount() external view returns (uint256) {
        return participants.length;
    }
}

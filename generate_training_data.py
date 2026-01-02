#!/usr/bin/env python3
"""
Generate additional synthetic training examples for Contract AI Auditor.
"""

import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.schema import TrainingExample, VulnerabilityType, SeverityLevel

def generate_synthetic_examples():
    """Generate synthetic training examples for different vulnerability types."""
    examples = []
    
    # Integer Overflow Example
    examples.append(TrainingExample(
        contract_code="""pragma solidity ^0.4.19;
contract IntegerOverflow {
    mapping(address => uint256) balances;
    
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}""",
        contract_name="IntegerOverflow",
        vulnerability_labels=[VulnerabilityType.INTEGER_OVERFLOW],
        severity_scores={VulnerabilityType.INTEGER_OVERFLOW: 0.8},
        explanations={VulnerabilityType.INTEGER_OVERFLOW: "Integer overflow/underflow vulnerability in arithmetic operations."},
        fixes={VulnerabilityType.INTEGER_OVERFLOW: "Use Solidity ^0.8.0 or SafeMath library."},
        source="synthetic",
        is_vulnerable=True
    ))
    
    # Access Control Example
    examples.append(TrainingExample(
        contract_code="""pragma solidity ^0.8.0;
contract AccessControl {
    address public owner;
    
    constructor() { owner = msg.sender; }
    
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}""",
        contract_name="AccessControl",
        vulnerability_labels=[VulnerabilityType.ACCESS_CONTROL],
        severity_scores={VulnerabilityType.ACCESS_CONTROL: 0.9},
        explanations={VulnerabilityType.ACCESS_CONTROL: "Missing access control on critical function."},
        fixes={VulnerabilityType.ACCESS_CONTROL: "Add onlyOwner modifier to restrict access."},
        source="synthetic",
        is_vulnerable=True
    ))
    
    # Safe Contract Example
    examples.append(TrainingExample(
        contract_code="""pragma solidity ^0.8.0;
contract SafeContract {
    address public owner;
    mapping(address => uint256) public balances;
    
    constructor() { owner = msg.sender; }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }
}""",
        contract_name="SafeContract",
        vulnerability_labels=[],
        severity_scores={},
        explanations={},
        fixes={},
        source="synthetic",
        is_vulnerable=False
    ))
    
    return examples

def main():
    """Generate and save synthetic training examples."""
    print("Generating synthetic training examples...")
    
    examples = generate_synthetic_examples()
    output_file = Path("data/processed/training_examples.jsonl")
    
    # Append to existing file
    with open(output_file, "a") as f:
        for example in examples:
            f.write(json.dumps(example.to_dict()) + "\n")
    
    print(f"Added {len(examples)} synthetic examples to {output_file}")
    
    # Check total count
    with open(output_file, "r") as f:
        total_examples = sum(1 for line in f)
    
    print(f"Total training examples: {total_examples}")

if __name__ == "__main__":
    main()
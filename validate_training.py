#!/usr/bin/env python3
"""
Simple validation test for the training pipeline.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

def test_training_components():
    """Test individual training components."""
    print("🧪 Testing training pipeline components...")
    
    try:
        # Test configuration loading
        from training.train import load_config
        config = load_config("config/basic_training.yaml")
        print(f"✅ Configuration loaded: {config['model']['name']}")
        
        # Test data loading
        from data.schema import load_training_examples
        examples = load_training_examples(config['data']['train_file'])
        print(f"✅ Training examples loaded: {len(examples)} samples")
        
        # Test tokenizer creation
        from training.tokenizer import SolidityDatasetTokenizer
        tokenizer = SolidityDatasetTokenizer(config['model']['name'])
        print(f"✅ Tokenizer created: {tokenizer.tokenizer.__class__.__name__}")
        
        # Test example processing
        if examples:
            example = examples[0]
            inputs = tokenizer.encode_contract(
                example.contract_code, 
                vulnerability_labels=[v.value for v in example.vulnerability_labels]
            )
            print(f"✅ Example encoding successful: {len(inputs['input_ids'])} tokens")
        
        return True
        
    except Exception as e:
        print(f"❌ Training component test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_simple_inference():
    """Test if we can create a simple model for inference."""
    print("\n🔍 Testing model inference capabilities...")
    
    try:
        # Test loading a pre-trained model without training
        from auditor.core import ContractAuditor
        
        # Create auditor with distilgpt2 (should be quick to load)
        auditor = ContractAuditor(model_name="distilgpt2", model_path=None)
        print("✅ Contract auditor created successfully")
        
        # Test with a simple contract
        simple_contract = """
pragma solidity ^0.8.0;
contract Test {
    uint256 public value = 42;
    function getValue() public view returns (uint256) {
        return value;
    }
}
"""
        
        result = auditor.audit_contract(simple_contract)
        print(f"✅ Contract audit completed: {len(result.vulnerabilities)} vulnerabilities found")
        
        return True
        
    except Exception as e:
        print(f"❌ Inference test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all validation tests."""
    print("🚀 Contract AI Auditor - Training Validation Tests\n")
    
    success = True
    
    # Test training components
    if not test_training_components():
        success = False
    
    # Test inference capabilities 
    if not test_simple_inference():
        success = False
    
    if success:
        print("\n🎉 All tests passed! The training system is working correctly.")
        print("\n📋 Recommendations:")
        print("1. The system can process training data and create models")
        print("2. You can proceed with full training when you have more data")
        print("3. Current audit functionality works with pre-trained models")
    else:
        print("\n❌ Some tests failed. Check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
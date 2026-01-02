#!/usr/bin/env python3
"""
Quick test script to validate training modules can be imported and basic functionality works.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing core imports...")
    
    try:
        from data.schema import VulnerabilityType, TrainingExample
        print("✅ Data schema imports successful")
    except ImportError as e:
        print(f"❌ Data schema import failed: {e}")
        return False
    
    try:
        from training.tokenizer import SolidityDatasetTokenizer
        print("✅ Tokenizer imports successful")
    except ImportError as e:
        print(f"❌ Tokenizer import failed: {e}")
        return False
    
    try:
        import torch
        import transformers
        print(f"✅ PyTorch {torch.__version__} and Transformers {transformers.__version__} available")
    except ImportError as e:
        print(f"❌ ML libraries import failed: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality without full training."""
    print("\nTesting basic functionality...")
    
    try:
        # Test vulnerability types
        from data.schema import VulnerabilityType
        print(f"✅ Found {len(VulnerabilityType)} vulnerability types")
        
        # Test tokenizer creation (without loading model)
        from training.tokenizer import SolidityDatasetTokenizer
        tokenizer = SolidityDatasetTokenizer("microsoft/DialoGPT-medium")
        print("✅ Tokenizer creation successful")
        
        # Test data loading
        from data.schema import load_training_examples
        print("✅ Data loading functions available")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Running Contract AI Auditor validation tests...\n")
    
    if not test_imports():
        print("\n❌ Import tests failed!")
        sys.exit(1)
    
    if not test_basic_functionality():
        print("\n❌ Functionality tests failed!")
        sys.exit(1)
    
    print("\n🎉 All tests passed! The system is ready for training.")
    print("\n📋 Next steps:")
    print("1. Collect more training data: python -m data.collect_data")
    print("2. Start training: python -m training.train --config config/basic_training.yaml")
    print("3. Audit contracts: python -m auditor.cli audit contract.sol")

if __name__ == "__main__":
    main()
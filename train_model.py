#!/usr/bin/env python3
"""
Simple script to train the model after data collection.

Usage:
    python train_model.py
    python train_model.py --data data/processed/forum_training_examples.jsonl
"""

import sys
import yaml
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from training.train import main as train_main

def main():
    """Train the model with collected forum data."""
    
    # Default paths
    training_data = Path("data/processed/forum_training_examples.jsonl")
    config_template = Path("training/configs/phi3_mini.yaml")
    output_dir = Path("checkpoints/forum-trained-model")
    
    # Check if training data exists
    if not training_data.exists():
        print(f"❌ Training data not found: {training_data}")
        print()
        print("Please collect data first:")
        print("  python train_with_forum_data.py --collect-only")
        return 1
    
    print("=" * 60)
    print("TRAINING CONTRACT AI AUDITOR MODEL")
    print("=" * 60)
    print(f"Training data: {training_data}")
    print(f"Output directory: {output_dir}")
    print()
    print("⚠️  If your computer freezes during model loading, use:")
    print("   python train_model_low_memory.py")
    print()
    
    # Load config template
    if not config_template.exists():
        print(f"❌ Config file not found: {config_template}")
        return 1
    
    with open(config_template, 'r') as f:
        config = yaml.safe_load(f)
    
    # Update config with actual data path
    config['data']['train_file'] = str(training_data.absolute())
    config['data']['validation_file'] = str(training_data.absolute())  # Will split automatically
    config['data']['test_file'] = str(training_data.absolute())
    config['training']['output_dir'] = str(output_dir.absolute())
    
    # Save updated config
    temp_config = Path("training/configs/temp_forum_training.yaml")
    temp_config.parent.mkdir(parents=True, exist_ok=True)
    with open(temp_config, 'w') as f:
        yaml.dump(config, f)
    
    print(f"✅ Config prepared: {temp_config}")
    print()
    print("Starting training...")
    print("=" * 60)
    print()
    
    # Override sys.argv to pass config to training script
    original_argv = sys.argv
    sys.argv = ["train.py", "--config", str(temp_config)]
    
    try:
        train_main()
        print()
        print("=" * 60)
        print("✅ TRAINING COMPLETE!")
        print("=" * 60)
        print(f"Model saved to: {output_dir}")
        print()
        print("You can now use the trained model:")
        print(f"  python neural_auditor.py <contract_file>")
        print("=" * 60)
        return 0
    except SystemExit as e:
        if e.code != 0:
            print()
            print("=" * 60)
            print("❌ TRAINING FAILED")
            print("=" * 60)
            print("Check the error messages above for details.")
            return e.code
        return 0
    except Exception as e:
        print()
        print("=" * 60)
        print("❌ TRAINING ERROR")
        print("=" * 60)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        sys.argv = original_argv

if __name__ == "__main__":
    sys.exit(main())




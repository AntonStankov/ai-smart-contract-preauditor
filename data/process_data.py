#!/usr/bin/env python3
"""
Data processing script for Contract AI Auditor.

This script processes raw audit data and creates train/validation/test splits.
"""

import argparse
import json
import logging
import random
import sys
from pathlib import Path
from typing import List

# Add project root to path  
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.schema import (
    TrainingExample, DatasetSplit, load_training_examples, save_training_examples
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_dataset_splits(
    examples: List[TrainingExample], 
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42
) -> DatasetSplit:
    """Create train/validation/test splits from training examples."""
    
    # Validate ratios
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 1e-6:
        raise ValueError("Split ratios must sum to 1.0")
    
    # Set random seed for reproducibility
    random.seed(random_seed)
    
    # Shuffle examples
    examples_shuffled = examples.copy()
    random.shuffle(examples_shuffled)
    
    n_total = len(examples_shuffled)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)
    n_test = n_total - n_train - n_val
    
    logger.info(f"Creating dataset splits:")
    logger.info(f"  Train: {n_train} examples ({train_ratio:.1%})")
    logger.info(f"  Validation: {n_val} examples ({val_ratio:.1%})")
    logger.info(f"  Test: {n_test} examples ({test_ratio:.1%})")
    
    # Create splits
    train_examples = examples_shuffled[:n_train]
    val_examples = examples_shuffled[n_train:n_train+n_val]
    test_examples = examples_shuffled[n_train+n_val:]
    
    return DatasetSplit(
        train=train_examples,
        validation=val_examples,
        test=test_examples
    )


def balance_dataset(examples: List[TrainingExample]) -> List[TrainingExample]:
    """Balance the dataset by vulnerability types."""
    
    # Separate vulnerable and safe examples
    vulnerable_examples = [ex for ex in examples if ex.is_vulnerable]
    safe_examples = [ex for ex in examples if not ex.is_vulnerable]
    
    logger.info(f"Original dataset: {len(vulnerable_examples)} vulnerable, {len(safe_examples)} safe")
    
    # If we have more safe than vulnerable examples, undersample safe examples
    if len(safe_examples) > len(vulnerable_examples):
        random.shuffle(safe_examples)
        safe_examples = safe_examples[:len(vulnerable_examples)]
        logger.info(f"Undersampled safe examples to {len(safe_examples)}")
    
    # If we have more vulnerable than safe examples, we might want to oversample
    # or collect more safe examples in the future
    
    balanced_examples = vulnerable_examples + safe_examples
    random.shuffle(balanced_examples)
    
    logger.info(f"Balanced dataset: {len(balanced_examples)} total examples")
    return balanced_examples


def main():
    parser = argparse.ArgumentParser(description="Process and split training data")
    parser.add_argument(
        "--input-file",
        default="data/processed/training_examples.jsonl",
        help="Input file with training examples"
    )
    parser.add_argument(
        "--output-dir",
        default="data/splits",
        help="Output directory for dataset splits"
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.7,
        help="Training set ratio"
    )
    parser.add_argument(
        "--val-ratio", 
        type=float,
        default=0.15,
        help="Validation set ratio"
    )
    parser.add_argument(
        "--test-ratio",
        type=float, 
        default=0.15,
        help="Test set ratio"
    )
    parser.add_argument(
        "--balance",
        action="store_true",
        help="Balance vulnerable/safe examples"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible splits"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load training examples
    input_file = Path(args.input_file)
    if not input_file.exists():
        logger.error(f"Input file {input_file} does not exist!")
        logger.info("Run data collection first: python data/collect_data.py")
        return 1
    
    logger.info(f"Loading training examples from {input_file}")
    examples = load_training_examples(str(input_file))
    logger.info(f"Loaded {len(examples)} training examples")
    
    if not examples:
        logger.error("No training examples found!")
        return 1
    
    # Balance dataset if requested
    if args.balance:
        examples = balance_dataset(examples)
    
    # Create dataset splits
    splits = create_dataset_splits(
        examples,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
        random_seed=args.seed
    )
    
    # Save splits
    train_file = output_dir / "train.jsonl"
    val_file = output_dir / "validation.jsonl"
    test_file = output_dir / "test.jsonl"
    
    save_training_examples(splits.train, str(train_file))
    save_training_examples(splits.validation, str(val_file))
    save_training_examples(splits.test, str(test_file))
    
    logger.info(f"Saved training split to {train_file}")
    logger.info(f"Saved validation split to {val_file}") 
    logger.info(f"Saved test split to {test_file}")
    
    # Save split statistics
    stats_file = output_dir / "split_stats.json"
    stats = splits.stats()
    stats["ratios"] = {
        "train_ratio": args.train_ratio,
        "val_ratio": args.val_ratio,
        "test_ratio": args.test_ratio
    }
    stats["balanced"] = args.balance
    stats["random_seed"] = args.seed
    
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)
    
    logger.info(f"Saved split statistics to {stats_file}")
    logger.info("Data processing completed!")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
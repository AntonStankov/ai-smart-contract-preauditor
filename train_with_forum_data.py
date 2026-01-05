#!/usr/bin/env python3
"""
Train the Contract AI Auditor using forum and web search data.

This script:
1. Collects vulnerability examples from Reddit, forums, and web searches
2. Processes the data into training examples
3. Trains the neural network model on this data
4. Saves the trained model for use in inference
"""

import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from data.forum_collectors import ForumTrainingDataCollector, create_forum_config
from data.schema import DatasetProcessor, save_training_examples, load_training_examples
from data.internet_collectors import InternetTrainingDataCollector, create_internet_config
from training.train import main as train_main
import argparse
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def collect_forum_training_data(config: dict = None) -> list:
    """Collect training data from forums and web searches."""
    if config is None:
        config = create_forum_config()
    
    logger.info("Starting forum and web search data collection...")
    
    # Collect from forums
    forum_collector = ForumTrainingDataCollector(config)
    forum_examples = forum_collector.collect_all_forum_data()
    
    # Convert to training examples
    all_training_examples = []
    for audit_data in forum_examples:
        examples = DatasetProcessor.audit_to_training_examples(audit_data)
        all_training_examples.extend(examples)
    
    logger.info(f"Collected {len(all_training_examples)} training examples from forums")
    
    # Also collect from existing internet sources
    internet_config = create_internet_config()
    internet_collector = InternetTrainingDataCollector(internet_config)
    internet_data = internet_collector.collect_all_internet_data()
    
    for source_name, audit_data_list in internet_data.items():
        for audit_data in audit_data_list:
            examples = DatasetProcessor.audit_to_training_examples(audit_data)
            all_training_examples.extend(examples)
    
    logger.info(f"Total training examples: {len(all_training_examples)}")
    
    return all_training_examples


def save_training_data(examples: list, output_path: str):
    """Save training examples to file."""
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    save_training_examples(examples, str(output_file))
    logger.info(f"Saved {len(examples)} training examples to {output_file}")
    
    # Print statistics
    vuln_types = {}
    for example in examples:
        for vuln_type in example.vulnerability_labels:
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    logger.info("Vulnerability type distribution:")
    for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
        logger.info(f"  {vuln_type.value}: {count}")


def main():
    """Main training pipeline."""
    parser = argparse.ArgumentParser(description="Train Contract AI Auditor with forum data")
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Only collect data, don't train"
    )
    parser.add_argument(
        "--train-only",
        action="store_true",
        help="Only train, skip data collection"
    )
    parser.add_argument(
        "--training-data",
        default="data/processed/forum_training_examples.jsonl",
        help="Path to training data file"
    )
    parser.add_argument(
        "--model-output",
        default="checkpoints/forum-trained-model",
        help="Output directory for trained model"
    )
    parser.add_argument(
        "--config",
        help="Path to training config file"
    )
    parser.add_argument(
        "--reddit-posts",
        type=int,
        default=200,
        help="Number of Reddit posts to collect"
    )
    parser.add_argument(
        "--stackoverflow-questions",
        type=int,
        default=150,
        help="Number of Stack Overflow questions to collect"
    )
    parser.add_argument(
        "--ethereum-se-questions",
        type=int,
        default=100,
        help="Number of Ethereum Stack Exchange questions to collect"
    )
    parser.add_argument(
        "--hackernews-stories",
        type=int,
        default=50,
        help="Number of Hacker News stories to collect"
    )
    parser.add_argument(
        "--web-results",
        type=int,
        default=100,
        help="Number of web search results to collect"
    )
    parser.add_argument(
        "--stackoverflow-api-key",
        help="Stack Overflow API key (optional, increases rate limits)"
    )
    
    args = parser.parse_args()
    
    # Collect training data
    if not args.train_only:
        logger.info("=" * 60)
        logger.info("STEP 1: Collecting training data from forums and web")
        logger.info("=" * 60)
        
        forum_config = create_forum_config()
        forum_config['reddit']['max_posts'] = args.reddit_posts
        forum_config['stackoverflow']['max_questions'] = args.stackoverflow_questions
        forum_config['ethereum_se']['max_questions'] = args.ethereum_se_questions
        forum_config['hackernews']['max_stories'] = args.hackernews_stories
        forum_config['web_search']['max_results'] = args.web_results
        
        if args.stackoverflow_api_key:
            forum_config['stackoverflow_api_key'] = args.stackoverflow_api_key
        
        training_examples = collect_forum_training_data(forum_config)
        
        if not training_examples:
            logger.error("No training examples collected! Cannot proceed with training.")
            return 1
        
        save_training_data(training_examples, args.training_data)
        
        if args.collect_only:
            logger.info("Data collection complete. Use --train-only to train the model.")
            return 0
    
    # Train the model
    if not args.collect_only:
        logger.info("=" * 60)
        logger.info("STEP 2: Training neural network model")
        logger.info("=" * 60)
        
        # Load training data
        if not Path(args.training_data).exists():
            logger.error(f"Training data file not found: {args.training_data}")
            logger.error("Run without --train-only to collect data first.")
            return 1
        
        training_examples = load_training_examples(args.training_data)
        logger.info(f"Loaded {len(training_examples)} training examples")
        
        # Update config file to point to training data
        config_path = args.config or "training/configs/phi3_mini_low_memory.yaml"  # Use low memory config
        config_file = Path(config_path)
        
        if config_file.exists():
            import yaml
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Update data path in config
            if 'data' not in config:
                config['data'] = {}
            config['data']['train_file'] = str(Path(args.training_data).absolute())
            
            # Save updated config temporarily
            temp_config_path = Path("training/configs/temp_forum_training.yaml")
            temp_config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(temp_config_path, 'w') as f:
                yaml.dump(config, f)
            
            config_path = str(temp_config_path)
            logger.info(f"Using config: {config_path}")
        
        # Prepare training arguments
        training_args = [
            "--config", config_path,
        ]
        
        # Override sys.argv for training script
        original_argv = sys.argv
        sys.argv = ["train.py"] + training_args
        
        try:
            # Call the training script
            logger.info("Starting model training...")
            logger.info(f"Training data: {args.training_data}")
            logger.info(f"Model output: {args.model_output}")
            train_main()
        except SystemExit as e:
            if e.code != 0:
                logger.error(f"Training failed with exit code {e.code}")
        except Exception as e:
            logger.error(f"Training error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            sys.argv = original_argv
        
        logger.info("=" * 60)
        logger.info("Training complete!")
        logger.info(f"Model saved to: {args.model_output}")
        logger.info("=" * 60)
        logger.info("You can now use the trained model for auditing:")
        logger.info(f"  python audit_any_contract.py <contract_file>")
        logger.info("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())


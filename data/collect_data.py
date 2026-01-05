#!/usr/bin/env python3
"""
Data collection script for Contract AI Auditor.

This script collects smart contract vulnerability data from various sources
including SWC Registry, Ethernaut, ImmuneFi, OpenZeppelin audits, etc.
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.collectors import DataCollector
from data.schema import save_training_examples, DatasetProcessor

# Try to import internet collectors
try:
    from data.internet_collectors import InternetTrainingDataCollector, create_internet_config
    HAS_INTERNET_COLLECTORS = True
except ImportError:
    HAS_INTERNET_COLLECTORS = False
    logger.warning("Internet collectors not available. Install requests library for internet data collection.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import internet collectors
try:
    from data.internet_collectors import InternetTrainingDataCollector, create_internet_config
    HAS_INTERNET_COLLECTORS = True
except ImportError:
    HAS_INTERNET_COLLECTORS = False
    logger.warning("Internet collectors not available. Install requests library for internet data collection.")


def main():
    parser = argparse.ArgumentParser(description="Collect smart contract vulnerability data")
    parser.add_argument(
        "--sources", 
        nargs="+",
        default=["swc"],
        choices=["swc", "ethernaut", "immunefi", "openzeppelin", "slither", "dvd", 
                "github", "etherscan", "internet", "all"],
        help="Data sources to collect from"
    )
    parser.add_argument(
        "--output-dir",
        default="data/raw",
        help="Output directory for raw data"
    )
    parser.add_argument(
        "--processed-dir",
        default="data/processed", 
        help="Output directory for processed training data"
    )
    parser.add_argument(
        "--cache-dir",
        default="data/cache",
        help="Cache directory for downloaded data"
    )
    parser.add_argument(
        "--internet-only",
        action="store_true",
        help="Only collect from internet sources"
    )
    parser.add_argument(
        "--github-token",
        help="GitHub personal access token for enhanced API limits"
    )
    parser.add_argument(
        "--etherscan-key",
        help="Etherscan API key for contract source code access"
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=5000,
        help="Maximum number of examples to collect"
    )
    
    args = parser.parse_args()
    
    # Handle internet vs local sources
    internet_sources = ["github", "etherscan"]
    local_sources = ["swc", "ethernaut", "immunefi", "openzeppelin", "slither", "dvd"]
    
    if args.internet_only:
        args.sources = internet_sources
    elif "internet" in args.sources:
        # Replace "internet" with actual internet sources
        args.sources = [s for s in args.sources if s != "internet"] + internet_sources
    elif "all" in args.sources:
        args.sources = local_sources + internet_sources
    
    # Expand 'all' to all available sources
    if "all" in args.sources:
        args.sources = local_sources + (internet_sources if HAS_INTERNET_COLLECTORS else [])
    
    # Create output directories
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    Path(args.processed_dir).mkdir(parents=True, exist_ok=True)
    Path(args.cache_dir).mkdir(parents=True, exist_ok=True)
    
    # Initialize collectors
    logger.info(f"Starting data collection from sources: {args.sources}")
    all_training_examples = []
    
    # Collect from local sources (existing behavior)
    local_to_collect = [s for s in args.sources if s in local_sources]
    if local_to_collect:
        collector = DataCollector(output_dir=args.output_dir)
        logger.info(f"Collecting from local sources: {local_to_collect}")
        
        for source_name in local_to_collect:
            try:
                logger.info(f"Collecting from {source_name}...")
                audit_data = collector.collect_source(source_name)
                
                # Convert to training examples
                for audit in audit_data:
                    examples = DatasetProcessor.audit_to_training_examples(audit)
                    all_training_examples.extend(examples)
                
                logger.info(f"Processed {len(audit_data)} audit records from {source_name}")
                
            except Exception as e:
                logger.error(f"Failed to collect from {source_name}: {e}")
                continue
    
    # Collect from internet sources (new functionality)  
    internet_to_collect = [s for s in args.sources if s in internet_sources]
    if internet_to_collect and HAS_INTERNET_COLLECTORS:
        logger.info(f"Collecting from internet sources: {internet_to_collect}")
        
        # Create internet collector configuration
        config = create_internet_config()
        if args.github_token:
            config['github']['token'] = args.github_token
        if args.etherscan_key:
            config['etherscan']['api_key'] = args.etherscan_key
        
        # Enable only requested sources
        for source in ['github', 'etherscan', 'swc_enhanced']:
            config[source]['enabled'] = source.replace('_enhanced', '') in internet_to_collect or 'swc' in internet_to_collect
        
        try:
            internet_collector = InternetTrainingDataCollector(config)
            internet_data = internet_collector.collect_all_internet_data()
            
            for source_name, audit_data in internet_data.items():
                if audit_data:
                    for audit in audit_data:
                        examples = DatasetProcessor.audit_to_training_examples(audit)
                        all_training_examples.extend(examples)
                    logger.info(f"Processed {len(audit_data)} audit records from {source_name}")
        except Exception as e:
            logger.error(f"Failed to collect from internet sources: {e}")
    elif internet_to_collect and not HAS_INTERNET_COLLECTORS:
        logger.warning("Internet sources requested but internet collectors not available")
    
    # Limit total examples if specified
    if len(all_training_examples) > args.max_examples:
        logger.info(f"Limiting to {args.max_examples} examples (collected {len(all_training_examples)})")
        all_training_examples = all_training_examples[:args.max_examples]
    
    if all_training_examples:
        # Save processed training examples
        output_file = Path(args.processed_dir) / "training_examples.jsonl"
        save_training_examples(all_training_examples, str(output_file))
        
        logger.info(f"Saved {len(all_training_examples)} training examples to {output_file}")
        
        # Print statistics
        vulnerable_count = sum(1 for ex in all_training_examples if ex.is_vulnerable)
        safe_count = len(all_training_examples) - vulnerable_count
        
        logger.info(f"Dataset statistics:")
        logger.info(f"  Total examples: {len(all_training_examples)}")
        logger.info(f"  Vulnerable contracts: {vulnerable_count}")
        logger.info(f"  Safe contracts: {safe_count}")
        
        # Vulnerability type distribution
        vuln_types = {}
        for example in all_training_examples:
            for vuln_type in example.vulnerability_labels:
                vuln_types[vuln_type.value] = vuln_types.get(vuln_type.value, 0) + 1
        
        if vuln_types:
            logger.info(f"  Vulnerability type distribution:")
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                logger.info(f"    {vuln_type}: {count}")
    
    else:
        logger.warning("No training examples were collected!")
    
    logger.info("Data collection completed!")


if __name__ == "__main__":
    main()
"""
Configuration and Integration Guide for Internet-Based Training Data Collection

This file shows how to integrate the internet-based data collection capabilities
into the existing Contract AI Auditor training pipeline.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List
import yaml

# Add the internet collectors to the existing data module
def integrate_internet_collectors():
    """
    Integration steps to add internet-based data collection to the existing system:
    
    1. Add internet collectors to data/__init__.py
    2. Modify collect_data.py to include internet sources
    3. Update configuration files
    4. Add API keys and credentials management
    """
    
    # Example configuration that can be added to config/training.yaml
    internet_config = {
        'internet_data_collection': {
            'enabled': True,
            'sources': {
                'github': {
                    'enabled': True,
                    'token_env_var': 'GITHUB_TOKEN',  # Set via environment variable
                    'repositories': [
                        'ConsenSys/smart-contract-best-practices',
                        'crytic/not-so-smart-contracts',
                        'sigp/solidity-security-blog',
                        'smartdec/classification',
                        'crytic/slither',
                    ],
                    'search_keywords': [
                        'reentrancy vulnerability',
                        'integer overflow solidity',
                        'access control bug',
                        'unchecked call'
                    ],
                    'max_results_per_search': 50
                },
                'etherscan': {
                    'enabled': True,
                    'api_key_env_var': 'ETHERSCAN_API_KEY',
                    'networks': ['mainnet', 'goerli'],  # Could expand to other networks
                    'known_vulnerable_addresses': [
                        # Add known vulnerable contract addresses
                        # These would come from public vulnerability databases
                    ]
                },
                'swc_enhanced': {
                    'enabled': True,
                    'github_repo': 'SmartContractSecurity/SWC-registry'
                },
                'academic_sources': {
                    'enabled': False,  # Requires more complex implementation
                    'arxiv_search_terms': [
                        'smart contract security',
                        'ethereum vulnerability',
                        'solidity bugs'
                    ]
                }
            },
            'rate_limiting': {
                'github': 1.0,      # 1 request per second
                'etherscan': 0.2,   # 5 requests per second (API limit)
                'default': 2.0      # Conservative default
            },
            'caching': {
                'enabled': True,
                'cache_dir': 'data/cache/internet',
                'max_age_days': 7,
                'cache_size_mb': 1000
            }
        }
    }
    
    return internet_config

def create_enhanced_collect_data_script():
    """
    Enhanced version of collect_data.py that includes internet sources.
    This shows how to modify the existing script.
    """
    
    enhanced_script = '''#!/usr/bin/env python3
"""
Enhanced data collection script with internet-based sources.
"""

import argparse
import logging
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.collectors import DataCollector
from data.internet_collectors import InternetTrainingDataCollector, create_internet_config
from data.schema import save_training_examples, DatasetProcessor

logger = logging.getLogger(__name__)

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
        "--internet-only",
        action="store_true",
        help="Only collect from internet sources"
    )
    parser.add_argument(
        "--github-token",
        help="GitHub API token for enhanced rate limits"
    )
    parser.add_argument(
        "--etherscan-key", 
        help="Etherscan API key"
    )
    # ... existing arguments ...
    
    args = parser.parse_args()
    
    # Handle internet sources
    internet_sources = ["github", "etherscan", "internet"]
    local_sources = ["swc", "ethernaut", "immunefi", "openzeppelin", "slither", "dvd"]
    
    if args.internet_only:
        args.sources = internet_sources
    elif "internet" in args.sources:
        args.sources.extend(internet_sources)
        args.sources.remove("internet")
    elif "all" in args.sources:
        args.sources = local_sources + internet_sources
    
    all_training_examples = []
    
    # Collect from local sources (existing collectors)
    local_to_collect = [s for s in args.sources if s in local_sources]
    if local_to_collect:
        collector = DataCollector(args.output_dir)
        for source in local_to_collect:
            try:
                logger.info(f"Collecting from local source: {source}")
                audit_data = collector.collect_source(source)
                examples = DatasetProcessor.audit_to_training_examples(audit_data)
                all_training_examples.extend(examples)
                logger.info(f"Generated {len(examples)} training examples from {source}")
            except Exception as e:
                logger.error(f"Failed to collect from {source}: {e}")
    
    # Collect from internet sources (new collectors)
    internet_to_collect = [s for s in args.sources if s in internet_sources]
    if internet_to_collect:
        # Create configuration
        config = create_internet_config()
        if args.github_token:
            config['github']['token'] = args.github_token
        if args.etherscan_key:
            config['etherscan']['api_key'] = args.etherscan_key
        
        # Initialize internet collector
        internet_collector = InternetTrainingDataCollector(config)
        
        try:
            logger.info("Collecting from internet sources...")
            internet_data = internet_collector.collect_all_internet_data()
            
            for source, audit_data in internet_data.items():
                if audit_data:
                    examples = DatasetProcessor.audit_to_training_examples(audit_data)
                    all_training_examples.extend(examples)
                    logger.info(f"Generated {len(examples)} training examples from {source}")
        except Exception as e:
            logger.error(f"Failed to collect from internet sources: {e}")
    
    # Save all training examples
    if all_training_examples:
        output_file = Path(args.processed_dir) / "training_examples.jsonl"
        save_training_examples(all_training_examples, str(output_file))
        logger.info(f"Saved {len(all_training_examples)} total training examples to {output_file}")
        
        # Print statistics
        vuln_types = {}
        for example in all_training_examples:
            for vuln_type in example.vulnerability_labels:
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        logger.info("Vulnerability type distribution:")
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {vuln_type}: {count}")
    else:
        logger.warning("No training examples were collected!")

if __name__ == "__main__":
    main()
'''
    
    return enhanced_script

def create_credentials_guide():
    """Guide for setting up API credentials safely."""
    
    guide = """
# Setting Up Internet Data Collection

## Required API Keys and Tokens

### GitHub Personal Access Token
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Create a new token with 'public_repo' scope
3. Set environment variable: `export GITHUB_TOKEN=your_token_here`

### Etherscan API Key  
1. Create account at https://etherscan.io
2. Go to API Keys section
3. Create new API key
4. Set environment variable: `export ETHERSCAN_API_KEY=your_key_here`

## Environment Setup

Create a `.env` file in your project root:

```bash
# GitHub API token for enhanced rate limits (60 -> 5000 requests/hour)
GITHUB_TOKEN=ghp_your_token_here

# Etherscan API key for contract source code access
ETHERSCAN_API_KEY=your_api_key_here

# Optional: Web3 provider for blockchain data
WEB3_PROVIDER_URL=https://mainnet.infura.io/v3/your_project_id
```

## Usage Examples

### Basic Internet Collection
```bash
python data/collect_data.py --sources github etherscan
```

### With API Keys
```bash
export GITHUB_TOKEN=your_token
export ETHERSCAN_API_KEY=your_key
python data/collect_data.py --sources internet
```

### Internet-only Collection
```bash
python data/collect_data.py --internet-only --github-token $GITHUB_TOKEN
```

## Rate Limiting and Ethical Considerations

- GitHub: 60 requests/hour without token, 5000 with token
- Etherscan: 5 requests/second with API key
- Always respect robots.txt and terms of service
- Use caching to avoid repeated requests
- Add delays between requests to be respectful

## Data Quality and Legal Considerations

1. **Public Data Only**: Only collect from public repositories and verified contracts
2. **License Compliance**: Respect software licenses of collected code
3. **Attribution**: Maintain source attribution in training data
4. **Privacy**: Don't collect private or sensitive information
5. **Terms of Service**: Comply with platform terms of service
"""
    
    return guide

def show_integration_benefits():
    """Show the benefits of internet-based training data collection."""
    
    benefits = {
        "Scale": [
            "Access to thousands of real-world contracts",
            "Much larger dataset than local examples",
            "Continuous data updates as new vulnerabilities are discovered"
        ],
        "Diversity": [
            "Real-world coding patterns and styles", 
            "Different Solidity versions and compiler settings",
            "Various DeFi, NFT, and other domain-specific contracts"
        ],
        "Quality": [
            "Verified contracts from Etherscan",
            "Curated examples from security researchers",
            "Professional audit findings and fixes"
        ],
        "Freshness": [
            "Latest vulnerability patterns and attack vectors",
            "Recent compiler bugs and security issues",
            "Up-to-date best practices and mitigations"
        ],
        "Coverage": [
            "Comprehensive vulnerability type coverage",
            "Edge cases and rare vulnerability patterns", 
            "Business logic vulnerabilities from real projects"
        ]
    }
    
    return benefits

def create_training_comparison():
    """Compare local vs internet-based training approaches."""
    
    comparison = {
        "Local Training (Current)": {
            "Pros": [
                "Fast and reliable",
                "No API dependencies", 
                "Consistent data quality",
                "No rate limiting"
            ],
            "Cons": [
                "Limited dataset size (~100s examples)",
                "May not cover all vulnerability types",
                "Synthetic examples may lack realism",
                "Static dataset doesn't improve over time"
            ],
            "Best for": [
                "Quick prototyping",
                "Offline development",
                "Basic model validation"
            ]
        },
        "Internet Training (Enhanced)": {
            "Pros": [
                "Large-scale datasets (10,000s examples)",
                "Real-world vulnerability patterns",
                "Comprehensive coverage of attack vectors",
                "Continuously updated with new findings"
            ],
            "Cons": [
                "Requires API keys and setup",
                "Rate limiting affects collection speed",
                "Network dependency",
                "Data quality varies"
            ],
            "Best for": [
                "Production model training",
                "Comprehensive vulnerability detection",
                "Research and development"
            ]
        },
        "Hybrid Approach (Recommended)": {
            "Description": "Combine local examples for reliable baseline with internet data for scale and diversity",
            "Implementation": [
                "Use local data for initial training and validation",
                "Enhance with internet data for production training",
                "Cache internet data locally for reliability",
                "Implement data quality filtering"
            ]
        }
    }
    
    return comparison

if __name__ == "__main__":
    print("=== Internet-Based Training Data Collection Integration Guide ===")
    print()
    
    print("Benefits of Internet-Based Collection:")
    benefits = show_integration_benefits()
    for category, items in benefits.items():
        print(f"\n{category}:")
        for item in items:
            print(f"  • {item}")
    
    print("\n" + "="*60)
    print("Training Approaches Comparison:")
    comparison = create_training_comparison()
    for approach, details in comparison.items():
        print(f"\n{approach}:")
        if "Pros" in details:
            print("  Pros:")
            for pro in details["Pros"]:
                print(f"    + {pro}")
        if "Cons" in details:
            print("  Cons:")
            for con in details["Cons"]:
                print(f"    - {con}")
        if "Description" in details:
            print(f"  {details['Description']}")
        if "Implementation" in details:
            print("  Implementation:")
            for step in details["Implementation"]:
                print(f"    → {step}")
    
    print("\n" + "="*60)
    print("Next Steps:")
    print("1. Set up API credentials (see credentials guide)")
    print("2. Install the internet_collectors.py module")
    print("3. Modify collect_data.py to include internet sources")
    print("4. Test collection with small datasets first")
    print("5. Scale up to full internet-based training")
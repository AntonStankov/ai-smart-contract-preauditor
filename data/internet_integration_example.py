"""
Example modification to integrate internet data collection into the existing system.
This shows the minimal changes needed to add internet-based training data collection.
"""

# Add these imports to the existing collect_data.py
import os
from data.internet_collectors import InternetTrainingDataCollector, create_internet_config

def collect_from_internet_sources(sources: list, github_token: str = None, etherscan_key: str = None) -> list:
    """
    Collect training data from internet sources.
    This function can be added to the existing collect_data.py script.
    """
    # Create configuration for internet collectors
    config = create_internet_config()
    
    # Set API credentials from environment variables or parameters
    if github_token or os.getenv('GITHUB_TOKEN'):
        config['github']['token'] = github_token or os.getenv('GITHUB_TOKEN')
    
    if etherscan_key or os.getenv('ETHERSCAN_API_KEY'):
        config['etherscan']['api_key'] = etherscan_key or os.getenv('ETHERSCAN_API_KEY')
    
    # Enable only requested sources
    internet_source_map = {
        'github': 'github',
        'etherscan': 'etherscan', 
        'swc-web': 'swc_enhanced'
    }
    
    for source in config.keys():
        if source in ['github', 'etherscan', 'swc_enhanced']:
            config[source]['enabled'] = any(s in internet_source_map.values() for s in sources)
    
    # Initialize and run internet data collection
    collector = InternetTrainingDataCollector(config)
    internet_data = collector.collect_all_internet_data()
    
    # Flatten the collected data
    all_examples = []
    for source_name, audit_data in internet_data.items():
        if audit_data:
            # Convert audit data to training examples
            from data.schema import DatasetProcessor
            examples = DatasetProcessor.audit_to_training_examples(audit_data)
            all_examples.extend(examples)
            print(f"Collected {len(examples)} examples from {source_name}")
    
    return all_examples

# Example of how to modify the main() function in collect_data.py
def enhanced_main_function():
    """
    This shows how to modify the existing main() function to support internet sources.
    """
    
    # Add these new command line arguments:
    parser.add_argument(
        "--include-internet",
        action="store_true", 
        help="Include internet-based data sources"
    )
    parser.add_argument(
        "--github-token",
        help="GitHub personal access token"
    )
    parser.add_argument(
        "--etherscan-key",
        help="Etherscan API key"
    )
    parser.add_argument(
        "--max-internet-examples",
        type=int,
        default=1000,
        help="Maximum examples to collect from internet sources"
    )
    
    # After parsing arguments, add this logic:
    """
    args = parser.parse_args()
    
    # Collect from local sources (existing code remains the same)
    local_examples = collect_local_data(args)  # existing function
    
    # Optionally collect from internet sources
    internet_examples = []
    if args.include_internet or any(source in ['github', 'etherscan'] for source in args.sources):
        internet_sources = [s for s in args.sources if s in ['github', 'etherscan']]
        if not internet_sources:
            internet_sources = ['github']  # default to GitHub
        
        print("Collecting from internet sources...")
        internet_examples = collect_from_internet_sources(
            internet_sources, 
            args.github_token, 
            args.etherscan_key
        )
        
        # Limit the number of internet examples if specified
        if len(internet_examples) > args.max_internet_examples:
            internet_examples = internet_examples[:args.max_internet_examples]
            print(f"Limited to {args.max_internet_examples} internet examples")
    
    # Combine all examples
    all_examples = local_examples + internet_examples
    print(f"Total examples collected: {len(all_examples)} ({len(local_examples)} local + {len(internet_examples)} internet)")
    """

def demonstrate_internet_collection():
    """
    Simple demonstration of how internet collection works.
    """
    print("=== Demonstrating Internet-Based Data Collection ===")
    
    # Check if required libraries are available
    try:
        import requests
        print("✓ requests library available - internet collection enabled")
    except ImportError:
        print("✗ requests library not available - install with: pip install requests")
        return
    
    # Create a simple configuration
    config = {
        'github': {
            'enabled': True,
            'token': os.getenv('GITHUB_TOKEN'),  # Optional but recommended
        },
        'etherscan': {
            'enabled': False,  # Disabled for demo
            'api_key': None
        },
        'swc_enhanced': {
            'enabled': True
        }
    }
    
    print("\nConfiguration:")
    for source, settings in config.items():
        status = "enabled" if settings.get('enabled') else "disabled"
        print(f"  {source}: {status}")
    
    # Show what would happen (without actually collecting)
    print("\nWhat internet collection would do:")
    print("1. GitHub repositories:")
    print("   - Search for vulnerable contract patterns")  
    print("   - Collect from known security research repos")
    print("   - Extract contracts and analyze for vulnerabilities")
    
    print("2. Enhanced SWC collection:")
    print("   - Fetch real examples from SWC registry GitHub")
    print("   - Process each SWC category")
    print("   - Generate training data with proper labels")
    
    print("3. Rate limiting and caching:")
    print("   - Respect API limits (1 req/sec for GitHub)")
    print("   - Cache responses to avoid repeated requests")
    print("   - Resume collection from cache if interrupted")
    
    print("\nTo enable full collection:")
    print("1. Set environment variable: export GITHUB_TOKEN=your_token")
    print("2. Run: python collect_data.py --include-internet")
    print("3. Or: python collect_data.py --sources github etherscan")

if __name__ == "__main__":
    demonstrate_internet_collection()
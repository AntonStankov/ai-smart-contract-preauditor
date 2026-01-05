# Forum and Web Search Training Guide

This guide explains how to train the Contract AI Auditor using data collected from forums, Reddit, web searches, and security discussions.

## Overview

The system now learns from:
- **Reddit discussions** (r/ethereum, r/solidity, r/ethdev)
- **Web searches** for vulnerability discussions
- **Security forums** and blog posts
- **GitHub security research** repositories
- **SWC registry** examples

The model uses a **neural network** instead of pattern matching, allowing it to understand context and learn from real-world discussions.

## Quick Start

### 1. Install Additional Dependencies

```bash
pip install -r requirements-forum.txt
```

### 2. Collect Training Data from Forums

```bash
# Collect data from Reddit and web searches
python train_with_forum_data.py --collect-only --reddit-posts 200 --web-results 100
```

This will:
- Collect security discussions from Reddit
- Search the web for vulnerability examples
- Extract Solidity code and vulnerability information
- Save training examples to `data/processed/forum_training_examples.jsonl`

### 3. Train the Model

```bash
# Train using the collected forum data
python train_with_forum_data.py --train-only
```

Or do both in one step:

```bash
# Collect data and train
python train_with_forum_data.py --reddit-posts 200 --web-results 100
```

### 4. Use the Trained Model

```bash
# Audit a contract using the neural network model
python neural_auditor.py contracts/vulnerable/reentrancy_victim.sol
```

## How It Works

### Data Collection

1. **Reddit Collector** (`data/forum_collectors.py`):
   - Searches security-related subreddits
   - Extracts Solidity code blocks from posts
   - Analyzes discussions to identify mentioned vulnerabilities
   - Creates training examples with vulnerability labels

2. **Web Search Collector**:
   - Searches for vulnerability discussions using DuckDuckGo
   - Fetches and parses web pages
   - Extracts code examples and vulnerability information
   - Creates training examples

3. **Forum Discussion Analysis**:
   - Identifies vulnerability types from discussion context
   - Extracts root causes and fixes from community discussions
   - Estimates severity based on discussion language
   - Links code examples to vulnerability descriptions

### Neural Network Model

The model architecture (`training/train.py`):
- **Base Model**: Code language model (Phi-3, CodeLLaMA, etc.)
- **Multi-task Learning**:
  - Vulnerability classification (which types are present)
  - Severity regression (how severe is each vulnerability)
  - Binary detection (is the contract vulnerable?)

### Inference Pipeline

The updated `auditor/core.py`:
- Uses model outputs instead of pattern matching
- Extracts vulnerability predictions from neural network logits
- Maps severity scores to severity levels
- Falls back to pattern matching only if model outputs are unavailable

## Configuration

### Forum Collection Config

Edit `data/forum_collectors.py` to customize:

```python
config = {
    'reddit': {
        'enabled': True,
        'max_posts': 200,
        'subreddits': ['ethereum', 'solidity', 'ethdev']
    },
    'web_search': {
        'enabled': True,
        'max_results': 100,
        'queries': [
            "solidity reentrancy vulnerability",
            "smart contract security audit",
            # Add more queries...
        ]
    }
}
```

### Training Config

Edit `training/configs/phi3_mini.yaml` or create a new config:

```yaml
model_name: "microsoft/phi-3-mini-4k-instruct"
learning_rate: 2e-5
num_train_epochs: 3
batch_size: 4
max_length: 2048
```

## Data Sources

### Reddit Subreddits
- `r/ethereum` - General Ethereum discussions
- `r/solidity` - Solidity programming
- `r/ethdev` - Ethereum development
- `r/ethtrader` - Trading discussions (sometimes has security topics)
- `r/defi` - DeFi discussions

### Web Search Queries
The system searches for:
- "solidity reentrancy vulnerability example"
- "smart contract integer overflow exploit"
- "ethereum access control bug"
- "defi flashloan attack code"
- "solidity security best practices"
- "smart contract audit findings"
- "ethereum vulnerability disclosure"

### GitHub Sources
- Security research repositories
- SWC registry examples
- Known vulnerable contract examples

## Training Process

1. **Data Collection** (15-30 minutes):
   - Collects posts and search results
   - Extracts code examples
   - Analyzes discussions for vulnerability mentions
   - Creates training examples

2. **Data Processing**:
   - Converts to training format
   - Splits into train/val/test sets
   - Tokenizes Solidity code

3. **Model Training** (30-60 minutes):
   - Fine-tunes base language model
   - Multi-task learning for classification and regression
   - Saves checkpoints

4. **Evaluation**:
   - Tests on held-out examples
   - Measures precision, recall, F1
   - Generates evaluation report

## Using the Trained Model

### Command Line

```bash
# Basic usage
python neural_auditor.py contract.sol

# Specify model path
python neural_auditor.py contract.sol --model checkpoints/forum-trained-model

# Output to specific file
python neural_auditor.py contract.sol --output my_report.md

# JSON output
python neural_auditor.py contract.sol --format json
```

### Python API

```python
from neural_auditor import NeuralContractAuditor

# Initialize auditor
auditor = NeuralContractAuditor(model_path="checkpoints/forum-trained-model")

# Audit a contract
result = auditor.audit_contract(contract_code, "MyContract")

# Access results
print(f"Found {len(result.vulnerabilities)} vulnerabilities")
for vuln in result.vulnerabilities:
    print(f"- {vuln.title}: {vuln.severity.value}")
```

## Advantages Over Pattern Matching

1. **Context Understanding**: Learns from discussions, not just code patterns
2. **Severity Assessment**: Neural network estimates severity, not just binary detection
3. **Adaptive Learning**: Can learn new vulnerability patterns from discussions
4. **Reduced False Positives**: Understands context to avoid false alarms
5. **Community Knowledge**: Incorporates insights from security discussions

## Limitations

1. **Training Data Quality**: Depends on quality of forum discussions
2. **Model Size**: Requires GPU for larger models
3. **Collection Time**: Web scraping takes time and respects rate limits
4. **False Positives**: May still have some false positives

## Troubleshooting

### "No trained model found"
- Train a model first: `python train_with_forum_data.py`
- Or specify model path: `--model path/to/model`

### "duckduckgo_search not installed"
- Install: `pip install duckduckgo-search`

### "Rate limit exceeded"
- Reddit and web searches have rate limits
- The system caches results to avoid repeated requests
- Wait and try again later

### "No training examples collected"
- Check internet connection
- Verify Reddit/web search is accessible
- Try increasing `--reddit-posts` and `--web-results`

## Next Steps

1. **Collect More Data**: Increase collection limits for better training
2. **Fine-tune Queries**: Add more specific search queries
3. **Add More Sources**: Extend collectors to more forums
4. **Evaluate Performance**: Test on known vulnerable contracts
5. **Continuous Learning**: Re-train periodically with new data

## Example Workflow

```bash
# 1. Collect training data (30 min)
python train_with_forum_data.py --collect-only --reddit-posts 500 --web-results 200

# 2. Train model (1 hour)
python train_with_forum_data.py --train-only

# 3. Test on vulnerable contract
python neural_auditor.py contracts/vulnerable/reentrancy_victim.sol

# 4. Review results
cat audit_report_reentrancy_victim.md
```

## Support

For issues or questions:
- Check logs in `data/cache/` for collection issues
- Review training logs for model training problems
- Test with `--collect-only` first to verify data collection




# Multi-Source Data Collection Guide

The Contract AI Auditor now collects training data from **multiple sources** beyond just Reddit, giving you access to a much richer dataset.

## Available Data Sources

### 1. **Reddit** ✅
- **Subreddits**: r/ethereum, r/solidity, r/ethdev, r/ethtrader, r/defi
- **What it collects**: Security discussions, code examples, vulnerability reports
- **Rate Limit**: ~60 requests/hour (unauthenticated)
- **Cache**: `data/cache/reddit/`

### 2. **Stack Overflow** ✅ NEW
- **Tags**: solidity, ethereum, smart-contracts, web3
- **What it collects**: Questions and answers about security vulnerabilities
- **Rate Limit**: 300 requests/day (unauthenticated), higher with API key
- **API Key**: Optional - get from https://stackapps.com/apps/oauth/register
- **Cache**: `data/cache/stackoverflow/`

### 3. **Ethereum Stack Exchange** ✅ NEW
- **Tags**: solidity, security, vulnerability
- **What it collects**: Ethereum-specific security questions and answers
- **Rate Limit**: Same as Stack Overflow (uses same API)
- **Cache**: `data/cache/ethereum_se/`

### 4. **Hacker News** ✅ NEW
- **What it collects**: Security-related stories and discussions
- **Rate Limit**: Firebase API, very generous
- **Cache**: `data/cache/hackernews/`

### 5. **Web Search** ✅
- **Queries**: Pre-configured security-related searches
- **What it collects**: Blog posts, articles, vulnerability disclosures
- **Search Engine**: DuckDuckGo (no API key required)
- **Cache**: `data/cache/websearch/`

### 6. **GitHub** (from existing collectors)
- **Repositories**: Security research repos, SWC registry
- **What it collects**: Vulnerable contract examples

## Quick Start

### Collect from All Sources

```bash
python train_with_forum_data.py --collect-only \
    --reddit-posts 200 \
    --stackoverflow-questions 150 \
    --ethereum-se-questions 100 \
    --hackernews-stories 50 \
    --web-results 100
```

### Collect from Specific Sources Only

Edit the config in `data/forum_collectors.py` or modify `train_with_forum_data.py`:

```python
forum_config = {
    'reddit': {'enabled': True, 'max_posts': 200},
    'stackoverflow': {'enabled': True, 'max_questions': 150},
    'ethereum_se': {'enabled': False},  # Disable this source
    'hackernews': {'enabled': True, 'max_stories': 50},
    'web_search': {'enabled': True, 'max_results': 100}
}
```

## Configuration

### Default Configuration

The default config collects from all sources:

```python
{
    'reddit': {
        'enabled': True,
        'max_posts': 200,
        'subreddits': ['ethereum', 'solidity', 'ethdev', 'ethtrader', 'defi']
    },
    'stackoverflow': {
        'enabled': True,
        'max_questions': 150,
        'tags': ['solidity', 'ethereum', 'smart-contracts', 'web3']
    },
    'ethereum_se': {
        'enabled': True,
        'max_questions': 100,
        'tags': ['solidity', 'security', 'vulnerability']
    },
    'hackernews': {
        'enabled': True,
        'max_stories': 50
    },
    'web_search': {
        'enabled': True,
        'max_results': 100,
        'queries': [
            "solidity reentrancy vulnerability",
            "smart contract security audit",
            "ethereum exploit code",
            "defi vulnerability disclosure"
        ]
    }
}
```

### Customizing Sources

#### Add More Reddit Subreddits

```python
'reddit': {
    'subreddits': ['ethereum', 'solidity', 'ethdev', 'cryptodevs', 'web3']
}
```

#### Add More Stack Overflow Tags

```python
'stackoverflow': {
    'tags': ['solidity', 'ethereum', 'smart-contracts', 'web3', 'blockchain']
}
```

#### Add More Web Search Queries

```python
'web_search': {
    'queries': [
        "solidity reentrancy vulnerability",
        "smart contract security audit",
        # Add your custom queries here
        "uniswap vulnerability",
        "compound finance exploit"
    ]
}
```

## Using API Keys (Optional)

### Stack Overflow API Key

1. Register at: https://stackapps.com/apps/oauth/register
2. Get your API key
3. Use it:

```bash
python train_with_forum_data.py \
    --stackoverflow-api-key YOUR_API_KEY \
    --stackoverflow-questions 500
```

Or set environment variable:

```bash
export STACKOVERFLOW_API_KEY=your_key_here
```

**Benefits of API Key**:
- Higher rate limits (10,000 requests/day vs 300)
- More reliable access
- Better for large-scale collection

## Collection Statistics

### Expected Collection Times

| Source | Items | Time | Notes |
|--------|-------|------|-------|
| Reddit | 200 posts | ~10 min | Rate limited |
| Stack Overflow | 150 questions | ~5 min | Fast API |
| Ethereum SE | 100 questions | ~3 min | Fast API |
| Hacker News | 50 stories | ~2 min | Very fast |
| Web Search | 100 results | ~15 min | Slower, fetches pages |

**Total**: ~35-40 minutes for full collection

### Expected Training Examples

| Source | Examples | Quality |
|--------|----------|---------|
| Reddit | 50-100 | Medium-High |
| Stack Overflow | 80-120 | High (expert answers) |
| Ethereum SE | 60-90 | High (domain-specific) |
| Hacker News | 10-20 | Medium (fewer code examples) |
| Web Search | 30-50 | Variable |

**Total**: ~230-380 training examples

## Advanced Usage

### Collect Only High-Quality Sources

If you want only the best sources:

```python
config = {
    'reddit': {'enabled': False},
    'stackoverflow': {'enabled': True, 'max_questions': 300},
    'ethereum_se': {'enabled': True, 'max_questions': 200},
    'hackernews': {'enabled': False},
    'web_search': {'enabled': True, 'max_results': 50}
}
```

### Incremental Collection

Collect from different sources at different times:

```bash
# Day 1: Reddit and Stack Overflow
python train_with_forum_data.py --collect-only \
    --reddit-posts 300 \
    --stackoverflow-questions 200 \
    --ethereum-se-questions 0 \
    --hackernews-stories 0 \
    --web-results 0

# Day 2: Ethereum SE and Hacker News
python train_with_forum_data.py --collect-only \
    --reddit-posts 0 \
    --stackoverflow-questions 0 \
    --ethereum-se-questions 200 \
    --hackernews-stories 100 \
    --web-results 0
```

## Troubleshooting

### "Rate limit exceeded" on Stack Overflow

- Get an API key for higher limits
- Reduce `--stackoverflow-questions`
- Wait 24 hours for limit reset

### "No examples collected from Hacker News"

- Hacker News has fewer code examples
- Try increasing `--hackernews-stories`
- Most value comes from linked articles

### "Web search collection slow"

- Web search fetches full pages (slower)
- Reduce `--web-results` if needed
- Results are cached for future runs

### "Stack Overflow API key not working"

- Verify key at https://stackapps.com/apps/oauth/register
- Check key format (should be alphanumeric)
- Ensure key has proper permissions

## Best Practices

1. **Start Small**: Test with small numbers first
2. **Use Caching**: All collectors cache results automatically
3. **Respect Rate Limits**: Don't set numbers too high
4. **Combine Sources**: Use multiple sources for diversity
5. **Regular Updates**: Re-collect periodically for fresh data

## Example Workflow

```bash
# 1. Collect from all sources (40 min)
python train_with_forum_data.py --collect-only \
    --reddit-posts 200 \
    --stackoverflow-questions 150 \
    --ethereum-se-questions 100 \
    --hackernews-stories 50 \
    --web-results 100

# 2. Train model (1-2 hours)
python train_with_forum_data.py --train-only

# 3. Test on vulnerable contract
python neural_auditor.py contracts/vulnerable/reentrancy_victim.sol
```

## Adding New Sources

To add a new source (e.g., Twitter, Discord):

1. Create a new collector class in `data/forum_collectors.py`
2. Inherit from `ForumDataCollector`
3. Implement collection methods
4. Add to `ForumTrainingDataCollector`
5. Update config in `create_forum_config()`

See existing collectors for examples!

## Summary

You now have access to:
- ✅ **5+ data sources** (Reddit, Stack Overflow, Ethereum SE, Hacker News, Web Search)
- ✅ **Hundreds of training examples** from diverse sources
- ✅ **High-quality discussions** from expert communities
- ✅ **Automatic caching** for efficient re-runs
- ✅ **Configurable collection** per source

This gives your model much richer training data than Reddit alone!




# Training Guide: How to Train After Data Collection

## Overview

**Collection and training are separate steps.** After you collect data from forums, you need to train the model separately.

## Step-by-Step Process

### Step 1: Collect Data (Already Done ✅)

You've already collected data using:
```bash
python train_with_forum_data.py --collect-only
```

This saved your training examples to: `data/processed/forum_training_examples.jsonl`

### Step 2: Train the Model

Now train the model with the collected data:

```bash
python train_with_forum_data.py --train-only
```

This will:
1. Load the collected training examples
2. Split into train/validation/test sets
3. Train the neural network model
4. Save the trained model to `checkpoints/forum-trained-model/`

## Alternative: Do Both in One Command

If you want to collect and train in one go:

```bash
python train_with_forum_data.py \
    --reddit-posts 200 \
    --stackoverflow-questions 150 \
    --ethereum-se-questions 100 \
    --hackernews-stories 50 \
    --web-results 100
```

This will:
1. Collect data from all sources
2. Automatically train the model after collection

## Manual Training (Advanced)

If you want more control, you can train manually:

### 1. Check Your Training Data

```bash
# See how many examples you have
python -c "
from data.schema import load_training_examples
examples = load_training_examples('data/processed/forum_training_examples.jsonl')
print(f'Total examples: {len(examples)}')
print(f'Vulnerable examples: {sum(1 for e in examples if e.is_vulnerable)}')
print(f'Safe examples: {sum(1 for e in examples if not e.is_vulnerable)}')
"
```

### 2. Train Using Training Script Directly

```bash
# First, update the config file to point to your data
# Edit training/configs/phi3_mini.yaml and set:
# data:
#   train_file: "data/processed/forum_training_examples.jsonl"

# Then train
python training/train.py --config training/configs/phi3_mini.yaml
```

## Training Configuration

The training uses a config file. Default is `training/configs/phi3_mini.yaml`.

### Key Settings:

```yaml
model:
  name: "microsoft/phi-3-mini-4k-instruct"  # Base model

data:
  train_file: "data/processed/forum_training_examples.jsonl"  # Your data

training:
  num_train_epochs: 3        # How many times to go through data
  per_device_train_batch_size: 4
  learning_rate: 2e-5
  warmup_ratio: 0.1

dataset:
  max_length: 2048          # Max code length
  train_split: 0.8         # 80% for training
  val_split: 0.1           # 10% for validation
  test_split: 0.1          # 10% for testing
```

## Training Time

Training time depends on:
- **Number of examples**: More examples = longer training
- **Model size**: Larger models = longer training
- **Hardware**: GPU is much faster than CPU

**Estimated times:**
- 200 examples: 30-60 minutes (CPU), 5-10 minutes (GPU)
- 500 examples: 1-2 hours (CPU), 15-30 minutes (GPU)
- 1000+ examples: 2-4 hours (CPU), 30-60 minutes (GPU)

## Monitoring Training

### Check Training Progress

The training script will show:
- Loss values (should decrease over time)
- Validation metrics
- Training speed

### Check Model Output

After training, check the output directory:
```bash
ls -la checkpoints/forum-trained-model/
```

You should see:
- `model.safetensors` - The trained model weights
- `config.json` - Model configuration
- `tokenizer.json` - Tokenizer files
- `training_args.bin` - Training arguments

## Using the Trained Model

Once training is complete, use the model:

```bash
# The neural auditor will auto-detect the trained model
python neural_auditor.py contracts/vulnerable/reentrancy_victim.sol

# Or specify the model path
python neural_auditor.py contracts/vulnerable/reentrancy_victim.sol \
    --model checkpoints/forum-trained-model
```

## Troubleshooting

### "Training data file not found"

Make sure you collected data first:
```bash
python train_with_forum_data.py --collect-only
```

Check if the file exists:
```bash
ls -lh data/processed/forum_training_examples.jsonl
```

### "No training examples loaded"

Your collected data might be empty. Check:
```bash
python -c "
from data.schema import load_training_examples
examples = load_training_examples('data/processed/forum_training_examples.jsonl')
print(f'Examples: {len(examples)}')
"
```

### "Out of memory" during training

Reduce batch size in config:
```yaml
training:
  per_device_train_batch_size: 2  # Reduce from 4 to 2
```

Or use a smaller model:
```yaml
model:
  name: "microsoft/phi-3-mini-4k-instruct"  # Already small
```

### Training is very slow

- Use GPU if available (much faster)
- Reduce `num_train_epochs` in config
- Reduce `max_length` in dataset config
- Use fewer training examples

## Quick Reference

```bash
# 1. Collect data only
python train_with_forum_data.py --collect-only

# 2. Train only (after collection)
python train_with_forum_data.py --train-only

# 3. Both in one command
python train_with_forum_data.py

# 4. Use trained model
python neural_auditor.py contract.sol
```

## Next Steps After Training

1. **Test the model** on known vulnerable contracts
2. **Evaluate performance** on test set
3. **Collect more data** if needed
4. **Re-train** with additional data
5. **Deploy** for production use

## Summary

- ✅ **Collection** = Gathering data from forums (already done)
- ⏳ **Training** = Teaching the model with that data (do this next)
- ✅ **Inference** = Using the trained model to audit contracts

**Next command to run:**
```bash
python train_with_forum_data.py --train-only
```




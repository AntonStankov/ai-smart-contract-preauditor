# Fix: Computer Freezes When Loading Model

## Problem

When training starts, your computer freezes at "Loading checkpoint shards". This happens because the model is too large for your available RAM.

## Quick Fix: Use Low-Memory Training

Use the low-memory training script instead:

```bash
python train_model_low_memory.py
```

This uses:
- **4-bit quantization** (reduces memory by ~75%)
- **Smaller batch sizes**
- **Gradient checkpointing**
- **Automatic device mapping**

## What Causes the Freeze?

1. **Model is too large**: Phi-3 Mini is ~7GB in full precision
2. **Loading into RAM**: Model tries to load all weights into memory at once
3. **System swap**: When RAM fills, system uses disk swap (very slow)
4. **Freeze**: System becomes unresponsive

## Solutions

### Solution 1: Use Low-Memory Config (Recommended)

```bash
# Install bitsandbytes for quantization
pip install bitsandbytes

# Train with low-memory config
python train_model_low_memory.py
```

**Benefits:**
- Reduces memory usage by ~75%
- Prevents freezing
- Still trains effectively

### Solution 2: Reduce Batch Size

Edit `training/configs/phi3_mini.yaml`:

```yaml
training:
  per_device_train_batch_size: 1  # Reduce from 16
  per_device_eval_batch_size: 2   # Reduce from 32
  gradient_accumulation_steps: 8  # Increase to maintain effective batch size
```

### Solution 3: Use CPU Offloading

Edit the config to use CPU offloading:

```yaml
model:
  device_map: "cpu"  # Load on CPU (slower but uses less GPU memory)
```

### Solution 4: Close Other Applications

Before training:
- Close browser tabs
- Close other applications
- Free up as much RAM as possible

### Solution 5: Use a Smaller Model

If Phi-3 Mini is still too large, consider:
- Using a smaller base model
- Training only the LoRA adapters (already enabled)

## Check Your System

### Check Available RAM

```bash
# Linux/Mac
free -h

# Or
cat /proc/meminfo | grep MemAvailable
```

**Minimum requirements:**
- **Without quantization**: 16GB+ RAM
- **With 4-bit quantization**: 8GB+ RAM
- **With 8-bit quantization**: 12GB+ RAM

### Check if Model is Downloading

The freeze might be because the model is downloading. Check:

```bash
# Check disk space
df -h

# Check if model is in cache
ls -lh ~/.cache/huggingface/hub/
```

## Step-by-Step Fix

1. **Install bitsandbytes**:
   ```bash
   pip install bitsandbytes
   ```

2. **Use low-memory training**:
   ```bash
   python train_model_low_memory.py
   ```

3. **Wait patiently**: Model loading takes 2-5 minutes even with optimizations

4. **Monitor progress**: You should see:
   ```
   Loading model microsoft/Phi-3-mini-4k-instruct...
   This may take a few minutes. Please wait...
   Loading checkpoint shards: 100%|████████| 2/2 [00:45<00:00, 22.5s/it]
   Model loaded successfully!
   ```

## If It Still Freezes

### Option 1: Use Even Smaller Config

Create `training/configs/phi3_mini_tiny.yaml`:

```yaml
training:
  per_device_train_batch_size: 1
  gradient_accumulation_steps: 16

data:
  max_length: 128  # Very short sequences
```

### Option 2: Train on Cloud

Use a cloud service with more RAM:
- Google Colab (free, 12GB RAM)
- Kaggle (free, 13GB RAM)
- AWS/GCP with GPU instances

### Option 3: Use Pattern Matching Instead

If training is not possible, use the pattern-matching auditor:

```bash
python audit_any_contract.py contract.sol
```

This doesn't require a trained model.

## Expected Behavior

**Normal loading (with low-memory config):**
- Takes 2-5 minutes
- Shows progress: "Loading checkpoint shards: X%"
- System remains responsive
- Eventually shows "Model loaded successfully!"

**Problematic loading:**
- Takes >10 minutes
- System becomes unresponsive
- No progress updates
- Computer freezes

## Summary

**Quick fix:**
```bash
pip install bitsandbytes
python train_model_low_memory.py
```

**If that doesn't work:**
- Check available RAM
- Close other applications
- Use even smaller batch sizes
- Consider cloud training

The low-memory config should prevent freezing in most cases!


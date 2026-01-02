# Training Guide

This guide covers how to train your own Contract AI Auditor models from scratch.

## Prerequisites

- Python 3.9+
- CUDA-capable GPU (recommended, 16GB+ VRAM for larger models)
- At least 32GB RAM
- 100GB+ free disk space
- Foundry (for testing)

## Quick Start

1. **Set up environment:**
```bash
# Clone and setup
git clone <repository-url>
cd contract-ai-auditor
./setup.sh

# Activate environment
source venv/bin/activate
```

2. **Collect training data:**
```bash
python data/collect_data.py --sources all
python data/process_data.py --balance
```

3. **Start training:**
```bash
python training/train.py --config training/configs/codellama_7b.yaml
```

## Dataset Preparation

### Data Collection

The system collects vulnerability data from multiple sources:

```bash
# Collect from specific sources
python data/collect_data.py --sources swc ethernaut immunefi

# Collect everything
python data/collect_data.py --sources all
```

### Data Processing

Process raw data into training-ready format:

```bash
# Basic processing
python data/process_data.py

# With balanced dataset
python data/process_data.py --balance --train-ratio 0.8 --val-ratio 0.1 --test-ratio 0.1
```

## Model Selection

Choose a base model based on your hardware and requirements:

### CodeLLaMA 7B (Recommended)
- **Hardware:** 16GB+ VRAM
- **Quality:** Excellent for code understanding
- **Config:** `training/configs/codellama_7b.yaml`

```bash
python training/train.py --config training/configs/codellama_7b.yaml
```

### StarCoder2 3B
- **Hardware:** 8GB+ VRAM  
- **Quality:** Good balance of size/performance
- **Config:** `training/configs/starcoder2_3b.yaml`

### DeepSeek-Coder 6.7B
- **Hardware:** 20GB+ VRAM
- **Quality:** Best for complex vulnerability detection
- **Config:** `training/configs/deepseek_coder_6_7b.yaml`

### Phi-3 Mini
- **Hardware:** 4GB+ VRAM
- **Quality:** Lightweight, good for basic detection
- **Config:** `training/configs/phi3_mini.yaml`

## Training Configuration

### Basic Configuration

```yaml
# training/configs/my_model.yaml
model:
  name: "codellama/CodeLlama-7b-hf"
  type: "causal_lm"
  use_flash_attention: true

lora:
  r: 16
  alpha: 32
  dropout: 0.1
  target_modules: ["q_proj", "v_proj", "k_proj", "o_proj"]

training:
  output_dir: "training/models/my-auditor"
  per_device_train_batch_size: 4
  num_train_epochs: 5
  learning_rate: 2e-4
```

### Key Parameters

- **LoRA rank (r):** Higher = more capacity but slower training
- **Learning rate:** Start with 2e-4, adjust based on loss curves
- **Batch size:** Limited by GPU memory
- **Epochs:** 3-8 epochs usually sufficient

### Multi-task Weights

Adjust task importance in training:

```yaml
tasks:
  vulnerability_classification:
    weight: 1.0      # Primary task
  severity_regression:
    weight: 0.5      # Secondary
  fix_generation:
    weight: 0.8      # Important for practical use
  explanation_generation:
    weight: 0.6      # Nice to have
```

## Training Process

### Monitor Training

Use Weights & Biases for experiment tracking:

```bash
# Enable W&B in config
experiment:
  use_wandb: true
  project_name: "contract-ai-auditor"
  run_name: "my-experiment"
```

Access dashboard at: https://wandb.ai/your-username/contract-ai-auditor

### Key Metrics to Watch

1. **Training Loss:** Should decrease steadily
2. **Validation F1:** Primary metric for vulnerability detection
3. **Severity RMSE:** Lower is better for severity prediction
4. **False Positive Rate:** Keep under 10% if possible

### Training Tips

1. **Start Small:** Begin with Phi-3 Mini to validate pipeline
2. **Use Gradient Accumulation:** If GPU memory is limited
3. **Enable Mixed Precision:** Saves memory and speeds training
4. **Early Stopping:** Prevent overfitting

```yaml
training:
  gradient_accumulation_steps: 4  # Effective batch size = batch_size * 4
  mixed_precision: "bf16"         # Use bfloat16
  early_stopping_patience: 3      # Stop if no improvement for 3 evals
```

## Advanced Training

### Custom Data

Add your own vulnerability data:

```python
from data.schema import ContractAuditData, Vulnerability, VulnerabilityType

# Create custom audit data
audit = ContractAuditData(
    contract_source=ContractSource(
        file_path="my_contract.sol",
        content=contract_code,
        compiler_version="0.8.0"
    ),
    contract_name="MyContract",
    vulnerabilities=[vulnerability],
    source_dataset="custom"
)

# Convert to training examples
examples = DatasetProcessor.audit_to_training_examples(audit)
```

### Distributed Training

For multiple GPUs:

```bash
# Single node, multiple GPUs
python -m torch.distributed.launch --nproc_per_node=4 \
    training/train.py --config training/configs/codellama_7b.yaml
```

### Quantization Training

For memory-efficient training:

```yaml
quantization:
  load_in_4bit: true
  bnb_4bit_compute_dtype: "bfloat16"
  bnb_4bit_use_double_quant: true
```

## Evaluation

Evaluate your trained model:

```bash
python evaluation/evaluate.py \
    --model-path training/models/my-auditor \
    --test-data data/splits/test.jsonl \
    --results-dir evaluation/reports
```

### Key Evaluation Metrics

1. **Precision/Recall per Vulnerability Type**
2. **Overall F1 Score**
3. **False Positive/Negative Rates** 
4. **Severity Assessment Accuracy**
5. **Fix Generation Quality**

## Troubleshooting

### Common Issues

**Out of Memory:**
```yaml
# Reduce batch size and use gradient accumulation
training:
  per_device_train_batch_size: 1
  gradient_accumulation_steps: 8
```

**Slow Training:**
```yaml
# Enable optimizations
model:
  use_flash_attention: true
  gradient_checkpointing: true
system:
  mixed_precision: "bf16"
  dataloader_num_workers: 4
```

**Poor Performance:**
- Check data quality and balance
- Adjust learning rate (try 1e-4 to 5e-4)
- Increase LoRA rank
- Add more training data

**Loss Not Decreasing:**
- Reduce learning rate
- Check for data leakage
- Verify tokenization is working correctly

## Best Practices

1. **Version Control:** Track model configs and results
2. **Reproducibility:** Set random seeds
3. **Validation:** Always use held-out validation set
4. **Testing:** Test on real contracts before deployment
5. **Documentation:** Document model performance and limitations

## Model Deployment

After training, deploy your model:

```python
from auditor.core import ContractAuditor

auditor = ContractAuditor(
    model_path="training/models/my-auditor",
    device="cuda",
    confidence_threshold=0.7
)

result = auditor.audit_contract(contract_code)
```

## Resources

- [Transformers Documentation](https://huggingface.co/docs/transformers)
- [PEFT Documentation](https://huggingface.co/docs/peft)
- [LoRA Paper](https://arxiv.org/abs/2106.09685)
- [Smart Contract Vulnerabilities](https://swcregistry.io/)

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review logs in `logs/` directory
3. Open an issue on GitHub
4. Join our Discord community
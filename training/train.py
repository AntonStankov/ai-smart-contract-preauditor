#!/usr/bin/env python3
"""
Training script for Contract AI Auditor models.

This script handles multi-task fine-tuning of code models for smart contract
security auditing using LoRA/QLoRA for efficient training.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
import yaml
import json
from typing import Dict, List, Optional, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
    from transformers import (
        AutoTokenizer, AutoModelForCausalLM, TrainingArguments,
        Trainer, EarlyStoppingCallback, TrainerCallback
    )
    from peft import LoraConfig, get_peft_model, TaskType
    from datasets import Dataset as HFDataset
    from sklearn.metrics import precision_recall_fscore_support, accuracy_score
    import numpy as np
    HAS_CORE_DEPS = True
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Please install core ML dependencies: pip install torch transformers peft datasets scikit-learn numpy")
    sys.exit(1)

# Optional dependencies
try:
    import wandb
    HAS_WANDB = True
except ImportError:
    HAS_WANDB = False
    print("Warning: wandb not available. Experiment tracking will be disabled.")

from data.schema import TrainingExample, load_training_examples, VulnerabilityType
from training.tokenizer import SolidityDatasetTokenizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ContractAuditDataset(Dataset):
    """Dataset for multi-task contract auditing training."""
    
    def __init__(
        self,
        examples: List[TrainingExample],
        tokenizer: SolidityDatasetTokenizer,
        max_length: int = 512,
        include_fixes: bool = True
    ):
        self.examples = examples
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.include_fixes = include_fixes
        
        # Create vulnerability type mapping
        self.vuln_types = list(VulnerabilityType)
        self.vuln_to_idx = {v: i for i, v in enumerate(self.vuln_types)}
        self.num_vuln_types = len(self.vuln_types)
        
        logger.info(f"Dataset created with {len(examples)} examples")
        logger.info(f"Vulnerability types: {len(self.vuln_types)}")
    
    def __len__(self) -> int:
        return len(self.examples)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        example = self.examples[idx]
        
        # Tokenize input code
        tokenized = self.tokenizer.prepare_training_data(
            vulnerable_code=example.contract_code,
            max_length=self.max_length
        )
        
        # Create vulnerability classification labels (multi-label binary)
        vuln_labels = torch.zeros(self.num_vuln_types, dtype=torch.float32)
        for vuln_type in example.vulnerability_labels:
            if vuln_type in self.vuln_to_idx:
                vuln_labels[self.vuln_to_idx[vuln_type]] = 1.0
        
        # Create severity scores (regression targets)
        severity_scores = torch.zeros(self.num_vuln_types, dtype=torch.float32)
        for vuln_type, score in example.severity_scores.items():
            if vuln_type in self.vuln_to_idx:
                severity_scores[self.vuln_to_idx[vuln_type]] = score
        
        result = {
            'input_ids': tokenized['input_ids'].squeeze(0),
            'attention_mask': tokenized['attention_mask'].squeeze(0),
            'vulnerability_labels': vuln_labels,
            'severity_scores': severity_scores,
            'is_vulnerable': torch.tensor(float(example.is_vulnerable), dtype=torch.float32),
            'contract_name': example.contract_name,
            'source': example.source
        }
        
        # Always add fix_input_ids (empty tensor if no fixes available)
        if self.include_fixes and example.fixes:
            fix_texts = []
            for vuln_type in self.vuln_types:
                if vuln_type in example.fixes:
                    fix_texts.append(example.fixes[vuln_type])
                else:
                    fix_texts.append("")
            
            # For now, just use the first available fix as target
            if any(fix_texts):
                first_fix = next(fix for fix in fix_texts if fix)
                fix_tokens = self.tokenizer.model_tokenizer(
                    first_fix,
                    truncation=True,
                    padding='max_length',
                    max_length=self.max_length,
                    return_tensors='pt'
                )
                result['fix_input_ids'] = fix_tokens['input_ids'].squeeze(0)
            else:
                # Create empty fix tokens if no fixes available
                result['fix_input_ids'] = torch.zeros(self.max_length, dtype=torch.long)
        elif self.include_fixes:
            # Create empty fix tokens if no fixes available
            result['fix_input_ids'] = torch.zeros(self.max_length, dtype=torch.long)
        
        return result


class MultiTaskAuditModel(nn.Module):
    """Multi-task model for contract auditing."""
    
    def __init__(
        self,
        base_model: nn.Module,
        num_vulnerability_types: int,
        hidden_size: int
    ):
        super().__init__()
        self.base_model = base_model
        self.hidden_size = hidden_size
        self.num_vuln_types = num_vulnerability_types
        
        # Task-specific heads
        self.vulnerability_classifier = nn.Linear(hidden_size, num_vulnerability_types)
        self.severity_regressor = nn.Linear(hidden_size, num_vulnerability_types)
        self.vulnerability_detector = nn.Linear(hidden_size, 1)  # Binary: vulnerable or not
        
        # Dropout for regularization
        self.dropout = nn.Dropout(0.1)
        
    def forward(self, input_ids, attention_mask, **kwargs):
        # Get base model outputs
        outputs = self.base_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_hidden_states=True
        )
        
        # Use last hidden state for classification/regression
        last_hidden_state = outputs.hidden_states[-1]
        pooled_output = last_hidden_state.mean(dim=1)  # Global average pooling
        pooled_output = self.dropout(pooled_output)
        
        # Task predictions
        vulnerability_logits = self.vulnerability_classifier(pooled_output)
        severity_predictions = self.severity_regressor(pooled_output)
        detection_logits = self.vulnerability_detector(pooled_output)
        
        return {
            'vulnerability_logits': vulnerability_logits,
            'severity_predictions': severity_predictions,
            'detection_logits': detection_logits,
            'base_logits': outputs.logits if hasattr(outputs, 'logits') else None
        }


class MultiTaskTrainer(Trainer):
    """Custom trainer for multi-task learning."""
    
    def __init__(self, task_weights: Dict[str, float] = None, **kwargs):
        super().__init__(**kwargs)
        self.task_weights = task_weights or {
            'vulnerability_classification': 1.0,
            'severity_regression': 0.5,
            'detection': 0.8,
            'generation': 0.3
        }
    
    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        """Compute multi-task loss."""
        outputs = model(**inputs)
        
        device = inputs['input_ids'].device
        total_loss = torch.tensor(0.0, device=device)
        
        # Vulnerability classification loss (multi-label binary cross-entropy)
        if 'vulnerability_labels' in inputs:
            vuln_loss = nn.BCEWithLogitsLoss()(
                outputs['vulnerability_logits'],
                inputs['vulnerability_labels']
            )
            total_loss += self.task_weights['vulnerability_classification'] * vuln_loss
        
        # Severity regression loss
        if 'severity_scores' in inputs:
            # Only compute loss where we have non-zero severity scores
            severity_mask = inputs['severity_scores'] > 0
            if severity_mask.any():
                severity_loss = nn.MSELoss()(
                    outputs['severity_predictions'][severity_mask],
                    inputs['severity_scores'][severity_mask]
                )
                total_loss += self.task_weights['severity_regression'] * severity_loss
        
        # Binary vulnerability detection loss
        if 'is_vulnerable' in inputs:
            detection_loss = nn.BCEWithLogitsLoss()(
                outputs['detection_logits'].squeeze(),
                inputs['is_vulnerable']
            )
            total_loss += self.task_weights['detection'] * detection_loss
        
        # Generation loss (if fix targets are available)
        if 'fix_input_ids' in inputs and outputs['base_logits'] is not None:
            # Shift labels for causal LM
            shift_labels = inputs['fix_input_ids'][..., 1:].contiguous()
            shift_logits = outputs['base_logits'][..., :-1, :].contiguous()
            
            gen_loss = nn.CrossEntropyLoss()(
                shift_logits.view(-1, shift_logits.size(-1)),
                shift_labels.view(-1)
            )
            total_loss += self.task_weights['generation'] * gen_loss
        
        return (total_loss, outputs) if return_outputs else total_loss
    
    def evaluate(
        self,
        eval_dataset=None,
        ignore_keys=None,
        metric_key_prefix="eval"
    ):
        """Enhanced evaluation with task-specific metrics."""
        eval_dataloader = self.get_eval_dataloader(eval_dataset)
        
        model = self.model
        model.eval()
        
        all_vuln_preds = []
        all_vuln_labels = []
        all_detection_preds = []
        all_detection_labels = []
        all_severity_preds = []
        all_severity_labels = []
        
        total_loss = 0.0
        num_batches = 0
        
        with torch.no_grad():
            for batch in eval_dataloader:
                batch = {k: v.to(self.args.device) for k, v in batch.items() 
                        if isinstance(v, torch.Tensor)}
                
                loss = self.compute_loss(model, batch)
                outputs = model(**batch)
                
                total_loss += loss.item()
                num_batches += 1
                
                # Collect predictions and labels
                vuln_probs = torch.sigmoid(outputs['vulnerability_logits'])
                vuln_preds = (vuln_probs > 0.5).float()
                all_vuln_preds.append(vuln_preds.cpu())
                all_vuln_labels.append(batch['vulnerability_labels'].cpu())
                
                detection_probs = torch.sigmoid(outputs['detection_logits'].squeeze())
                detection_preds = (detection_probs > 0.5).float()
                all_detection_preds.append(detection_preds.cpu())
                all_detection_labels.append(batch['is_vulnerable'].cpu())
                
                all_severity_preds.append(outputs['severity_predictions'].cpu())
                all_severity_labels.append(batch['severity_scores'].cpu())
        
        # Compute metrics
        all_vuln_preds = torch.cat(all_vuln_preds, dim=0)
        all_vuln_labels = torch.cat(all_vuln_labels, dim=0)
        all_detection_preds = torch.cat(all_detection_preds, dim=0)
        all_detection_labels = torch.cat(all_detection_labels, dim=0)
        
        # Vulnerability classification metrics (macro-averaged)
        vuln_precision, vuln_recall, vuln_f1, _ = precision_recall_fscore_support(
            all_vuln_labels.numpy(), all_vuln_preds.numpy(), average='macro', zero_division=0
        )
        
        # Detection metrics
        detection_accuracy = accuracy_score(all_detection_labels.numpy(), all_detection_preds.numpy())
        
        # Severity regression metrics (RMSE)
        severity_preds = torch.cat(all_severity_preds, dim=0)
        severity_labels = torch.cat(all_severity_labels, dim=0)
        severity_mask = severity_labels > 0
        severity_rmse = 0.0
        if severity_mask.any():
            severity_rmse = torch.sqrt(torch.mean(
                (severity_preds[severity_mask] - severity_labels[severity_mask]) ** 2
            )).item()
        
        eval_loss = total_loss / num_batches
        
        metrics = {
            f"{metric_key_prefix}_loss": eval_loss,
            f"{metric_key_prefix}_vulnerability_precision": vuln_precision,
            f"{metric_key_prefix}_vulnerability_recall": vuln_recall,
            f"{metric_key_prefix}_vulnerability_f1": vuln_f1,
            f"{metric_key_prefix}_detection_accuracy": detection_accuracy,
            f"{metric_key_prefix}_severity_rmse": severity_rmse,
            f"{metric_key_prefix}_combined_score": (vuln_f1 + detection_accuracy) / 2
        }
        
        self.log(metrics)
        return metrics


def load_config(config_path: str) -> Dict:
    """Load training configuration from YAML file."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config


def create_model_and_tokenizer(config: Dict) -> Tuple[nn.Module, SolidityDatasetTokenizer]:
    """Create and configure model and tokenizer."""
    model_name = config['model']['name']
    
    # Load tokenizer
    tokenizer = SolidityDatasetTokenizer(model_name)
    
    # Load base model
    model_kwargs = {
        'trust_remote_code': config['model'].get('trust_remote_code', False)
    }
    
    # Add quantization config if specified
    if config.get('quantization', {}).get('load_in_4bit'):
        try:
            from transformers import BitsAndBytesConfig
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=config['quantization'].get('bnb_4bit_use_double_quant', True),
                bnb_4bit_quant_type=config['quantization'].get('bnb_4bit_quant_type', 'nf4')
            )
            model_kwargs['quantization_config'] = quantization_config
        except ImportError:
            logger.warning("BitsAndBytesConfig not available. Install with: pip install bitsandbytes")
            logger.warning("Falling back to fp16 loading")
            model_kwargs['torch_dtype'] = torch.float16
    elif config.get('quantization', {}).get('load_in_8bit'):
        model_kwargs['load_in_8bit'] = True
    
    base_model = AutoModelForCausalLM.from_pretrained(model_name, **model_kwargs)
    
    # Resize token embeddings for special tokens
    base_model.resize_token_embeddings(tokenizer.get_vocab_size())
    
    # Apply LoRA if configured
    if 'lora' in config:
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=config['lora']['r'],
            lora_alpha=config['lora']['alpha'],
            lora_dropout=config['lora']['dropout'],
            target_modules=config['lora']['target_modules'],
            use_rslora=config['lora'].get('use_rslora', False)
        )
        base_model = get_peft_model(base_model, lora_config)
    
    # Wrap in multi-task model
    hidden_size = base_model.config.hidden_size
    num_vuln_types = len(VulnerabilityType)
    
    model = MultiTaskAuditModel(base_model, num_vuln_types, hidden_size)
    
    return model, tokenizer


def create_datasets(config: Dict, tokenizer: SolidityDatasetTokenizer) -> Tuple[ContractAuditDataset, ContractAuditDataset, ContractAuditDataset]:
    """Create train, validation, and test datasets."""
    
    # Load data - handle both single file and separate files
    if 'validation_file' in config['data'] and 'test_file' in config['data']:
        # Separate files provided
        train_examples = load_training_examples(config['data']['train_file'])
        val_examples = load_training_examples(config['data']['validation_file'])
        test_examples = load_training_examples(config['data']['test_file'])
    else:
        # Single file - split automatically
        all_examples = load_training_examples(config['data']['train_file'])
        
        # Get split ratios from config
        train_ratio = config['dataset'].get('train_split', 0.8)
        val_ratio = config['dataset'].get('val_split', 0.1)
        test_ratio = config['dataset'].get('test_split', 0.1)
        
        # Calculate split indices
        n_total = len(all_examples)
        n_train = int(n_total * train_ratio)
        n_val = int(n_total * val_ratio)
        
        # Split the data
        train_examples = all_examples[:n_train]
        val_examples = all_examples[n_train:n_train + n_val]
        test_examples = all_examples[n_train + n_val:]
        
        logger.info(f"Split {n_total} examples: {len(train_examples)} train, {len(val_examples)} val, {len(test_examples)} test")
    
    max_length = config['dataset'].get('max_length', 512)
    
    # Create datasets
    train_dataset = ContractAuditDataset(train_examples, tokenizer, max_length, include_fixes=False)
    val_dataset = ContractAuditDataset(val_examples, tokenizer, max_length, include_fixes=False)
    test_dataset = ContractAuditDataset(test_examples, tokenizer, max_length, include_fixes=False)
    
    return train_dataset, val_dataset, test_dataset


def main():
    parser = argparse.ArgumentParser(description="Train Contract AI Auditor model")
    parser.add_argument(
        "--config",
        required=True,
        help="Path to training configuration file"
    )
    parser.add_argument(
        "--resume-from-checkpoint",
        help="Path to checkpoint to resume from"
    )
    parser.add_argument(
        "--local-rank",
        type=int,
        default=-1,
        help="Local rank for distributed training"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Set up experiment tracking
    if config['experiment'].get('use_wandb', True) and HAS_WANDB:
        wandb.init(
            project=config['experiment']['project_name'],
            name=config['experiment']['run_name'],
            tags=config['experiment']['tags'],
            config=config
        )
    elif config['experiment'].get('use_wandb', True) and not HAS_WANDB:
        logger.warning("W&B requested but not available. Install with: pip install wandb")
    
    # Create model and tokenizer
    logger.info("Creating model and tokenizer...")
    model, tokenizer = create_model_and_tokenizer(config)
    
    # Create datasets
    logger.info("Loading datasets...")
    train_dataset, val_dataset, test_dataset = create_datasets(config, tokenizer)
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=config['training']['output_dir'],
        per_device_train_batch_size=int(config['training']['per_device_train_batch_size']),
        per_device_eval_batch_size=int(config['training']['per_device_eval_batch_size']),
        gradient_accumulation_steps=int(config['training']['gradient_accumulation_steps']),
        num_train_epochs=int(config['training']['num_train_epochs']),
        learning_rate=float(config['training']['learning_rate']),
        weight_decay=float(config['training']['weight_decay']),
        warmup_ratio=float(config['training']['warmup_ratio']),
        lr_scheduler_type=config['training']['lr_scheduler_type'],
        optim=config['training']['optim'],
        max_grad_norm=float(config['training']['max_grad_norm']),
        eval_strategy=config['training']['eval_strategy'],  # Updated parameter name
        eval_steps=int(config['training']['eval_steps']),
        save_strategy=config['training']['save_strategy'],
        save_steps=int(config['training']['save_steps']),
        logging_steps=int(config['training']['logging_steps']),
        load_best_model_at_end=bool(config['training']['load_best_model_at_end']),
        metric_for_best_model=config['training']['metric_for_best_model'],
        greater_is_better=False,  # Fixed: eval_loss should be minimized
        dataloader_pin_memory=bool(config['training'].get('dataloader_pin_memory', False)),
        bf16=config['system']['mixed_precision'] == 'bf16',
        fp16=config['system']['mixed_precision'] == 'fp16',
        dataloader_num_workers=config['system']['dataloader_num_workers'],
        disable_tqdm=config['system']['disable_tqdm'],
        report_to=config['system']['report_to'],
        remove_unused_columns=False,  # Keep all columns for multi-task learning
    )
    
    # Extract task weights from config
    task_weights = {
        'vulnerability_classification': config['tasks']['classification']['weight'],
        'severity_regression': config['tasks']['severity']['weight'],
        'detection': config['tasks']['classification']['weight'],  # Use classification weight for detection
        'generation': config['tasks']['generation']['weight']
    }
    
    # Create trainer
    trainer = MultiTaskTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        task_weights=task_weights,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
    )
    
    # Start training
    logger.info("Starting training...")
    if args.resume_from_checkpoint:
        trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)
    else:
        trainer.train()
    
    # Save final model
    logger.info("Saving final model...")
    trainer.save_model()
    tokenizer.model_tokenizer.save_pretrained(config['training']['output_dir'])
    
    # Final evaluation on test set
    logger.info("Evaluating on test set...")
    test_metrics = trainer.evaluate(test_dataset, metric_key_prefix="test")
    
    # Save test results
    results_file = Path(config['training']['output_dir']) / "test_results.json"
    with open(results_file, 'w') as f:
        json.dump(test_metrics, f, indent=2)
    
    logger.info(f"Training completed! Results saved to {results_file}")
    
    if config['experiment'].get('use_wandb', True) and HAS_WANDB:
        wandb.finish()


if __name__ == "__main__":
    main()
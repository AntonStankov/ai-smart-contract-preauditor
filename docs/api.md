# API Reference

This document provides comprehensive API documentation for the Contract AI Auditor.

## Core Classes

### ContractAuditor

Main interface for smart contract auditing.

```python
from auditor.core import ContractAuditor

auditor = ContractAuditor(
    model_path="path/to/model",
    device="auto",
    confidence_threshold=0.7
)
```

#### Constructor Parameters

- `model_path` (str): Path to trained model directory
- `device` (str, optional): Device to use ("auto", "cpu", "cuda", "mps"). Default: "auto"
- `confidence_threshold` (float, optional): Minimum confidence for vulnerability detection. Default: 0.7
- `batch_size` (int, optional): Batch size for inference. Default: 1

#### Methods

##### audit_contract()

Audit a single smart contract.

```python
result = auditor.audit_contract(
    contract_code="pragma solidity ^0.8.0; contract Test { ... }",
    contract_name="TestContract",
    analyze_gas=True
)
```

**Parameters:**
- `contract_code` (str): Solidity source code
- `contract_name` (str, optional): Name of the contract. Default: "UnknownContract"
- `analyze_gas` (bool, optional): Whether to perform gas analysis. Default: True

**Returns:** `AuditResult`

##### audit_file()

Audit a contract from a file.

```python
result = auditor.audit_file("contracts/MyContract.sol")
```

**Parameters:**
- `filepath` (str | Path): Path to Solidity file

**Returns:** `AuditResult`

##### batch_audit()

Audit multiple contracts in batch.

```python
contracts = [
    ("contract code 1", "Contract1"),
    ("contract code 2", "Contract2")
]

results = auditor.batch_audit(
    contracts=contracts,
    progress_callback=lambda current, total, name: print(f"{current}/{total}: {name}")
)
```

**Parameters:**
- `contracts` (List[Tuple[str, str]]): List of (contract_code, contract_name) pairs
- `progress_callback` (callable, optional): Progress callback function

**Returns:** `List[AuditResult]`

##### generate_report()

Generate formatted audit report.

```python
report = auditor.generate_report(result, format="markdown")
```

**Parameters:**
- `result` (AuditResult): Audit result to format
- `format` (str, optional): Output format ("markdown", "html", "txt"). Default: "markdown"

**Returns:** `str` - Formatted report

### AuditResult

Container for audit results.

```python
@dataclass
class AuditResult:
    contract_name: str
    contract_source: str
    vulnerabilities: List[Vulnerability]
    overall_severity: SeverityLevel
    confidence_score: float
    audit_timestamp: datetime
    model_version: str
    gas_analysis: Optional[Dict] = None
```

#### Methods

##### to_dict()

Convert to dictionary for JSON serialization.

```python
data = result.to_dict()
```

##### to_json()

Convert to JSON string.

```python
json_str = result.to_json()
```

##### save_to_file()

Save audit result to file.

```python
result.save_to_file("audit_result.json")
```

## Data Schema Classes

### VulnerabilityType

Enumeration of supported vulnerability types.

```python
from data.schema import VulnerabilityType

# Available types
VulnerabilityType.REENTRANCY
VulnerabilityType.INTEGER_OVERFLOW
VulnerabilityType.ACCESS_CONTROL
VulnerabilityType.UNCHECKED_CALL
# ... and more
```

### SeverityLevel

Vulnerability severity levels.

```python
from data.schema import SeverityLevel

SeverityLevel.CRITICAL
SeverityLevel.HIGH
SeverityLevel.MEDIUM
SeverityLevel.LOW
SeverityLevel.INFO
```

### Vulnerability

Individual vulnerability information.

```python
@dataclass
class Vulnerability:
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    impact: List[VulnerabilityImpact]
    location: VulnerabilityLocation
    affected_code: str
    title: str
    description: str
    root_cause: str
    recommended_fix: str
    fixed_code: Optional[str] = None
    confidence: float = 1.0
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
```

### VulnerabilityLocation

Code location information.

```python
@dataclass
class VulnerabilityLocation:
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    function_name: Optional[str] = None
    contract_name: Optional[str] = None
```

## Training Classes

### ContractAuditDataset

PyTorch dataset for training.

```python
from training.train import ContractAuditDataset

dataset = ContractAuditDataset(
    examples=training_examples,
    tokenizer=tokenizer,
    max_length=512
)
```

### MultiTaskAuditModel

Multi-task model architecture.

```python
from training.train import MultiTaskAuditModel

model = MultiTaskAuditModel(
    base_model=base_model,
    num_vulnerability_types=len(VulnerabilityType),
    hidden_size=4096
)
```

## Evaluation Classes

### ModelEvaluator

Comprehensive model evaluation.

```python
from evaluation.evaluator import ModelEvaluator

evaluator = ModelEvaluator(auditor)
metrics = evaluator.evaluate_model(
    test_examples=test_data,
    save_results=True,
    results_dir="evaluation/reports"
)
```

### VulnerabilityMetrics

Metrics for vulnerability detection performance.

```python
@dataclass
class VulnerabilityMetrics:
    vulnerability_type: str
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    support: int
    auc: Optional[float] = None
```

## Testing Framework

### ContractTester

Framework for testing vulnerability exploits and fixes.

```python
from tests.testing_framework import ContractTester, test_audit_with_foundry

# Test audit result
results = test_audit_with_foundry(
    audit_result=audit_result,
    fixed_contract_code=fixed_code,
    save_report=True
)
```

### TestResult

Result of contract testing.

```python
@dataclass
class TestResult:
    contract_name: str
    vulnerability_type: VulnerabilityType
    exploit_successful: bool
    fix_successful: bool
    compilation_successful: bool
    gas_usage: Optional[int] = None
    error_message: Optional[str] = None
```

## Tokenization

### SolidityTokenizer

Custom tokenizer for Solidity code.

```python
from training.tokenizer import SolidityTokenizer

tokenizer = SolidityTokenizer()
tokens = tokenizer.tokenize(contract_code)
vulnerabilities = tokenizer.detect_vulnerabilities(contract_code)
```

### SolidityDatasetTokenizer

Dataset-specific tokenizer with model integration.

```python
from training.tokenizer import SolidityDatasetTokenizer

tokenizer = SolidityDatasetTokenizer("microsoft/CodeBERT-base")
encoded = tokenizer.prepare_training_data(
    vulnerable_code=code,
    vulnerability_type="reentrancy"
)
```

## CLI Interface

### Command Line Usage

```bash
# Audit single contract
audit-contract --model-path ./models/auditor --contract-file contract.sol

# Batch audit
audit-contract --model-path ./models/auditor --contract-files "contracts/*.sol" --output-dir ./results

# Generate reports
audit-contract --model-path ./models/auditor --contract-file contract.sol --output-format markdown --output-file report.md
```

### CLI Arguments

**Global Arguments:**
- `--model-path`: Path to trained model (required)
- `--device`: Device for inference ("auto", "cpu", "cuda", "mps")
- `--confidence-threshold`: Minimum confidence for reporting
- `--output-format`: Report format ("markdown", "html", "txt")
- `--verbose`: Enable verbose logging

**Single Contract:**
- `contract_file`: Path to Solidity file
- `--output-file`: Output file for report
- `--json-output`: Save JSON result to file

**Batch Audit:**
- `contract_files`: Contract files or directories (supports globs)
- `--output-dir`: Output directory for results

## Configuration Files

### Training Configuration

YAML configuration for training:

```yaml
model:
  name: "codellama/CodeLlama-7b-hf"
  type: "causal_lm"
  use_flash_attention: true

lora:
  r: 16
  alpha: 32
  dropout: 0.1
  target_modules: ["q_proj", "v_proj"]

training:
  output_dir: "training/models/my-model"
  per_device_train_batch_size: 4
  num_train_epochs: 5
  learning_rate: 2e-4

data:
  max_length: 2048
  train_file: "data/splits/train.jsonl"
  validation_file: "data/splits/validation.jsonl"

tasks:
  vulnerability_classification:
    weight: 1.0
  severity_regression:
    weight: 0.5
```

## Error Handling

### Common Exceptions

```python
# Model loading errors
try:
    auditor = ContractAuditor("invalid/path")
except FileNotFoundError:
    print("Model path does not exist")

# Contract parsing errors  
try:
    result = auditor.audit_contract("invalid solidity code")
except Exception as e:
    print(f"Audit failed: {e}")

# Device errors
try:
    auditor = ContractAuditor("model/path", device="cuda")
except RuntimeError:
    print("CUDA not available")
```

### Error Messages

The library provides detailed error messages for common issues:

- Model loading failures
- Invalid Solidity code
- Device compatibility issues
- Memory constraints
- File I/O errors

## Performance Considerations

### Memory Usage

- **Small models (Phi-3):** ~4GB VRAM
- **Medium models (StarCoder2):** ~8GB VRAM  
- **Large models (CodeLLaMA):** ~16GB VRAM

### Optimization Tips

```python
# Use appropriate device
auditor = ContractAuditor(
    model_path="path/to/model",
    device="cuda",  # Use GPU if available
    batch_size=4    # Increase for better throughput
)

# Enable optimizations in training config
model:
  use_flash_attention: true
  gradient_checkpointing: true

system:
  mixed_precision: "bf16"
```

## Examples

### Basic Usage

```python
from auditor.core import ContractAuditor

# Initialize auditor
auditor = ContractAuditor("models/my-auditor")

# Audit contract
with open("MyContract.sol", "r") as f:
    contract_code = f.read()

result = auditor.audit_contract(contract_code, "MyContract")

# Print summary
print(f"Found {len(result.vulnerabilities)} vulnerabilities")
print(f"Overall severity: {result.overall_severity.value}")

# Generate report
report = auditor.generate_report(result, "markdown")
print(report)
```

### Advanced Usage

```python
from auditor.core import ContractAuditor
from tests.testing_framework import test_audit_with_foundry

# Audit with testing
auditor = ContractAuditor("models/auditor", confidence_threshold=0.8)
result = auditor.audit_contract(vulnerable_code, "VulnerableContract")

# Test exploits
test_results = test_audit_with_foundry(
    audit_result=result,
    fixed_contract_code=fixed_code
)

# Check if exploits work and fixes are effective
for test_result in test_results:
    if test_result.exploit_successful and test_result.fix_successful:
        print(f"✓ {test_result.vulnerability_type.value}: Exploit works, fix effective")
```

## Migration Guide

### From v0.1 to v0.2

- `ContractAuditor.audit()` → `ContractAuditor.audit_contract()`
- Added `batch_audit()` method
- Changed confidence scoring scale
- New CLI interface

### From v0.2 to v0.3

- Multi-task training support
- Enhanced tokenizer
- Testing framework integration
- Breaking changes in schema classes
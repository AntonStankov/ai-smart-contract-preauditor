# Dataset Schema

This document describes the data structures and schema used by the Contract AI Auditor for training and evaluation.

## Overview

The system uses a hierarchical data model that captures:
- Smart contract source code
- Vulnerability information
- Severity assessments  
- Fix recommendations
- Training metadata

## Core Schema Classes

### ContractSource

Represents smart contract source code and compilation metadata.

```python
@dataclass
class ContractSource:
    file_path: str              # Path to source file
    content: str                # Solidity source code
    compiler_version: str       # Solidity compiler version
    optimizer_enabled: bool     # Whether optimizer was enabled
    optimizer_runs: int         # Number of optimizer runs
    metadata: Dict             # Additional metadata
```

**Example:**
```python
source = ContractSource(
    file_path="contracts/Token.sol",
    content="pragma solidity ^0.8.0; contract Token { ... }",
    compiler_version="0.8.19",
    optimizer_enabled=True,
    optimizer_runs=200,
    metadata={"license": "MIT"}
)
```

### VulnerabilityType

Enumeration of supported vulnerability types based on SWC registry and common patterns.

```python
class VulnerabilityType(Enum):
    # SWC Categories
    REENTRANCY = "SWC-107"
    INTEGER_OVERFLOW = "SWC-101"
    UNCHECKED_CALL = "SWC-104"
    ACCESS_CONTROL = "SWC-105"
    DOS_GAS_LIMIT = "SWC-128"
    TIMESTAMP_DEPENDENCE = "SWC-116"
    TX_ORIGIN = "SWC-115"
    DELEGATECALL = "SWC-112"
    UNINITIALIZED_STORAGE = "SWC-109"
    FLOATING_PRAGMA = "SWC-103"
    
    # Additional common vulnerabilities
    FRONT_RUNNING = "FRONT_RUNNING"
    FLASHLOAN_ATTACK = "FLASHLOAN_ATTACK"
    PRICE_MANIPULATION = "PRICE_MANIPULATION"
    SANDWICH_ATTACK = "SANDWICH_ATTACK"
    MEV_VULNERABILITY = "MEV_VULNERABILITY"
```

### SeverityLevel

Vulnerability severity classification.

```python
class SeverityLevel(Enum):
    CRITICAL = "critical"  # Immediate threat to funds
    HIGH = "high"         # Significant risk, probable exploitation
    MEDIUM = "medium"     # Moderate risk, specific conditions
    LOW = "low"          # Minor risk, edge cases
    INFO = "info"        # Code quality, gas optimization
```

### VulnerabilityImpact

Types of impact a vulnerability can have.

```python
class VulnerabilityImpact(Enum):
    FUNDS_LOSS = "funds_loss"
    FUNDS_LOCK = "funds_lock"
    DOS = "denial_of_service"
    GOVERNANCE = "governance_manipulation"
    PRIVACY = "privacy_breach"
    GAS_GRIEF = "gas_griefing"
    CODE_QUALITY = "code_quality"
```

### VulnerabilityLocation

Precise location information for vulnerabilities.

```python
@dataclass
class VulnerabilityLocation:
    line_start: int                    # Starting line number (1-indexed)
    line_end: int                     # Ending line number
    column_start: int = 0             # Starting column (0-indexed)
    column_end: int = 0              # Ending column
    function_name: Optional[str] = None    # Function containing vulnerability
    contract_name: Optional[str] = None    # Contract containing vulnerability
```

### Vulnerability

Complete vulnerability information.

```python
@dataclass
class Vulnerability:
    # Classification
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    impact: List[VulnerabilityImpact]
    
    # Location and context
    location: VulnerabilityLocation
    affected_code: str
    
    # Descriptions
    title: str
    description: str
    root_cause: str
    exploit_scenario: Optional[str] = None
    
    # Fix information
    recommended_fix: str
    fixed_code: Optional[str] = None
    gas_impact: Optional[str] = None
    
    # Metadata
    confidence: float = 1.0        # 0.0 to 1.0
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
```

### ContractAuditData

Complete audit information for a smart contract.

```python
@dataclass
class ContractAuditData:
    # Contract information
    contract_source: ContractSource
    contract_name: str
    contract_address: Optional[str] = None
    
    # Vulnerabilities
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    # Overall assessment
    overall_severity: SeverityLevel = SeverityLevel.INFO
    total_issues: int = 0
    
    # Audit metadata
    audit_date: datetime = field(default_factory=datetime.now)
    auditor: Optional[str] = None
    version: str = "1.0"
    
    # Training metadata
    source_dataset: Optional[str] = None  # e.g., "SWC", "Immunefi"
    is_synthetic: bool = False
```

### TrainingExample

Individual training example for model training.

```python
@dataclass
class TrainingExample:
    # Input
    contract_code: str
    contract_name: str
    
    # Outputs for different tasks
    vulnerability_labels: List[VulnerabilityType] = field(default_factory=list)
    severity_scores: Dict[VulnerabilityType, float] = field(default_factory=dict)
    explanations: Dict[VulnerabilityType, str] = field(default_factory=dict)
    fixes: Dict[VulnerabilityType, str] = field(default_factory=dict)
    
    # Metadata
    source: str = ""
    is_vulnerable: bool = True
```

### DatasetSplit

Train/validation/test splits for training.

```python
@dataclass
class DatasetSplit:
    train: List[TrainingExample]
    validation: List[TrainingExample]
    test: List[TrainingExample]
```

## Data Processing Pipeline

### 1. Raw Data Collection

Data is collected from various sources:
- **SWC Registry:** Known vulnerability patterns
- **OpenZeppelin Audits:** Professional audit reports
- **Immunefi:** Bug bounty disclosures
- **Ethernaut:** Educational challenges
- **Damn Vulnerable DeFi:** DeFi-specific vulnerabilities
- **Slither:** Static analysis test corpus

### 2. Data Normalization

Raw data is converted to `ContractAuditData` objects:

```python
from data.collectors import SWCCollector

collector = SWCCollector()
audit_data = collector.collect_all()  # Returns List[ContractAuditData]
```

### 3. Training Example Generation

Audit data is converted to training examples:

```python
from data.schema import DatasetProcessor

examples = DatasetProcessor.audit_to_training_examples(audit_data)
```

### 4. Dataset Splits

Examples are split into train/validation/test sets:

```python
from data.process_data import create_dataset_splits

splits = create_dataset_splits(
    examples,
    train_ratio=0.7,
    val_ratio=0.15,
    test_ratio=0.15
)
```

## File Formats

### JSONL Format

Training examples are stored in JSONL (JSON Lines) format:

```json
{"contract_code": "pragma solidity...", "contract_name": "Token", "vulnerability_labels": ["SWC-107"], ...}
{"contract_code": "pragma solidity...", "contract_name": "Exchange", "vulnerability_labels": [], ...}
```

### JSON Schema Validation

Example JSON schema for validation:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "contract_code": {"type": "string"},
    "contract_name": {"type": "string"},
    "vulnerability_labels": {
      "type": "array",
      "items": {"type": "string"}
    },
    "severity_scores": {"type": "object"},
    "explanations": {"type": "object"},
    "fixes": {"type": "object"},
    "source": {"type": "string"},
    "is_vulnerable": {"type": "boolean"}
  },
  "required": ["contract_code", "contract_name"]
}
```

## Data Statistics

### Typical Dataset Composition

| Source | Contracts | Vulnerabilities | Severity Distribution |
|--------|-----------|----------------|-----------------------|
| SWC Registry | ~50 | ~100 | 30% Critical, 40% High, 30% Medium |
| Ethernaut | ~25 | ~25 | 40% High, 35% Medium, 25% Low |
| Immunefi | ~200 | ~300 | 50% Critical, 30% High, 20% Medium |
| OpenZeppelin | ~100 | ~150 | 20% Critical, 50% High, 30% Medium |

### Vulnerability Type Distribution

```
Reentrancy:           25%
Access Control:       20%
Integer Overflow:     15%
Unchecked Calls:      12%
Gas Limit DoS:        8%
Timestamp Depend.:    6%
Other:                14%
```

## Quality Assurance

### Data Validation

All data goes through validation:

```python
def validate_training_example(example: TrainingExample) -> bool:
    # Check required fields
    if not example.contract_code or not example.contract_name:
        return False
    
    # Validate vulnerability labels
    for vuln_type in example.vulnerability_labels:
        if vuln_type not in VulnerabilityType:
            return False
    
    # Check severity scores are in valid range
    for score in example.severity_scores.values():
        if not 0.0 <= score <= 1.0:
            return False
    
    return True
```

### Deduplication

Contracts are deduplicated based on:
- Normalized source code hash
- Contract bytecode hash
- Function signature similarity

### Balance

Dataset is balanced to prevent bias:
- Equal representation of vulnerable/safe contracts
- Proportional vulnerability type distribution
- Severity level balance

## Custom Data Integration

### Adding New Sources

To add a custom data source:

1. **Create Collector Class:**
```python
class MyCustomCollector:
    def collect_all(self) -> List[ContractAuditData]:
        # Implement data collection logic
        pass
```

2. **Register with DataCollector:**
```python
collector = DataCollector()
collector.collectors["my_source"] = MyCustomCollector()
```

### Custom Vulnerability Types

To add new vulnerability types:

1. **Extend VulnerabilityType enum:**
```python
class CustomVulnerabilityType(VulnerabilityType):
    MY_VULN = "CUSTOM-001"
```

2. **Update tokenizer patterns:**
```python
VULNERABILITY_PATTERNS = {
    'my_vulnerability': [
        r'pattern1',
        r'pattern2'
    ]
}
```

## Schema Evolution

### Version History

- **v1.0:** Initial schema with basic vulnerability types
- **v1.1:** Added DeFi-specific vulnerabilities
- **v1.2:** Enhanced location information
- **v2.0:** Multi-task learning support

### Migration

When schema changes, migration utilities are provided:

```python
from data.migrations import migrate_v1_to_v2

old_data = load_v1_data("old_dataset.jsonl")
new_data = migrate_v1_to_v2(old_data)
save_v2_data(new_data, "new_dataset.jsonl")
```

## Best Practices

### Data Collection

1. **Diversity:** Include contracts from different domains
2. **Quality:** Verify vulnerability labels manually
3. **Recency:** Keep dataset updated with new vulnerability patterns
4. **Balance:** Maintain proportional representation

### Labeling Guidelines

1. **Consistency:** Use standardized vulnerability classifications
2. **Completeness:** Include all relevant vulnerabilities
3. **Accuracy:** Verify fixes actually resolve issues
4. **Context:** Provide sufficient explanations

### Processing

1. **Validation:** Always validate data integrity
2. **Versioning:** Track data versions and changes  
3. **Reproducibility:** Use deterministic splits
4. **Documentation:** Document data sources and processing steps
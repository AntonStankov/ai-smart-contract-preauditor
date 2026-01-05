"""
Dataset Schema for Contract AI Auditor

This module defines the data structures and schemas used for training
the smart contract security auditing model.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union
from datetime import datetime
import json


class VulnerabilityType(Enum):
    """Smart contract vulnerability types based on SWC registry and common patterns."""
    
    # SWC Categories
    REENTRANCY = "SWC-107"  # Reentrancy
    INTEGER_OVERFLOW = "SWC-101"  # Integer Overflow/Underflow
    UNCHECKED_CALL = "SWC-104"  # Unchecked Return Value for Low Level Calls
    ACCESS_CONTROL = "SWC-105"  # Unprotected Ether Withdrawal
    DOS_GAS_LIMIT = "SWC-128"  # DoS with Block Gas Limit
    TIMESTAMP_DEPENDENCE = "SWC-116"  # Block values as proxy for time
    TX_ORIGIN = "SWC-115"  # Authorization through tx.origin
    DELEGATECALL = "SWC-112"  # Delegatecall to Untrusted Callee
    UNINITIALIZED_STORAGE = "SWC-109"  # Uninitialized Storage Pointer
    FLOATING_PRAGMA = "SWC-103"  # Floating Pragma
    
    # Additional common vulnerabilities
    FRONT_RUNNING = "FRONT_RUNNING"
    FLASHLOAN_ATTACK = "FLASHLOAN_ATTACK" 
    PRICE_MANIPULATION = "PRICE_MANIPULATION"
    SANDWICH_ATTACK = "SANDWICH_ATTACK"
    MEV_VULNERABILITY = "MEV_VULNERABILITY"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    
    CRITICAL = "critical"  # Immediate threat to funds or contract functionality
    HIGH = "high"         # Significant risk, probable exploitation
    MEDIUM = "medium"     # Moderate risk, possible exploitation under specific conditions
    LOW = "low"          # Minor risk, edge case scenarios
    INFO = "info"        # Code quality, gas optimization, best practices


class VulnerabilityImpact(Enum):
    """Types of impact a vulnerability can have."""
    
    FUNDS_LOSS = "funds_loss"
    FUNDS_LOCK = "funds_lock" 
    DOS = "denial_of_service"
    GOVERNANCE = "governance_manipulation"
    PRIVACY = "privacy_breach"
    GAS_GRIEF = "gas_griefing"
    CODE_QUALITY = "code_quality"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class ContractSource:
    """Source information for a smart contract."""
    
    file_path: str
    content: str
    compiler_version: str
    optimizer_enabled: bool = False
    optimizer_runs: int = 200
    metadata: Dict = field(default_factory=dict)


@dataclass
class VulnerabilityLocation:
    """Location of a vulnerability in source code."""
    
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    function_name: Optional[str] = None
    contract_name: Optional[str] = None


@dataclass
class Vulnerability:
    """A single vulnerability instance."""
    
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
    
    # Fix information
    recommended_fix: str
    
    # Optional fields with defaults
    exploit_scenario: Optional[str] = None
    fixed_code: Optional[str] = None
    gas_impact: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class ContractAuditData:
    """Complete audit data for a smart contract."""
    
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
    source_dataset: Optional[str] = None  # e.g., "SWC", "Immunefi", "Ethernaut"
    is_synthetic: bool = False
    
    def __post_init__(self):
        """Calculate derived fields."""
        self.total_issues = len(self.vulnerabilities)
        if self.vulnerabilities:
            severities = [v.severity for v in self.vulnerabilities]
            if SeverityLevel.CRITICAL in severities:
                self.overall_severity = SeverityLevel.CRITICAL
            elif SeverityLevel.HIGH in severities:
                self.overall_severity = SeverityLevel.HIGH
            elif SeverityLevel.MEDIUM in severities:
                self.overall_severity = SeverityLevel.MEDIUM
            elif SeverityLevel.LOW in severities:
                self.overall_severity = SeverityLevel.LOW


@dataclass
class TrainingExample:
    """A single training example for the model."""
    
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
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "contract_code": self.contract_code,
            "contract_name": self.contract_name,
            "vulnerability_labels": [v.value for v in self.vulnerability_labels],
            "severity_scores": {k.value: v for k, v in self.severity_scores.items()},
            "explanations": {k.value: v for k, v in self.explanations.items()},
            "fixes": {k.value: v for k, v in self.fixes.items()},
            "source": self.source,
            "is_vulnerable": self.is_vulnerable
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "TrainingExample":
        """Create instance from dictionary."""
        return cls(
            contract_code=data["contract_code"],
            contract_name=data["contract_name"],
            vulnerability_labels=[VulnerabilityType(v) for v in data.get("vulnerability_labels", [])],
            severity_scores={VulnerabilityType(k): v for k, v in data.get("severity_scores", {}).items()},
            explanations={VulnerabilityType(k): v for k, v in data.get("explanations", {}).items()},
            fixes={VulnerabilityType(k): v for k, v in data.get("fixes", {}).items()},
            source=data.get("source", ""),
            is_vulnerable=data.get("is_vulnerable", True)
        )


@dataclass
class DatasetSplit:
    """Dataset splits for training, validation, and testing."""
    
    train: List[TrainingExample]
    validation: List[TrainingExample]
    test: List[TrainingExample]
    
    def stats(self) -> Dict[str, int]:
        """Get dataset statistics."""
        return {
            "train_size": len(self.train),
            "validation_size": len(self.validation), 
            "test_size": len(self.test),
            "total_size": len(self.train) + len(self.validation) + len(self.test)
        }


class DatasetProcessor:
    """Utility class for processing and converting audit data to training examples."""
    
    @staticmethod
    def audit_to_training_examples(audit: ContractAuditData) -> List[TrainingExample]:
        """Convert audit data to training examples."""
        examples = []
        
        # Create positive example (vulnerable contract)
        if audit.vulnerabilities:
            vulnerability_labels = [v.vulnerability_type for v in audit.vulnerabilities]
            severity_scores = {v.vulnerability_type: DatasetProcessor._severity_to_score(v.severity) 
                             for v in audit.vulnerabilities}
            explanations = {v.vulnerability_type: v.description for v in audit.vulnerabilities}
            fixes = {v.vulnerability_type: v.recommended_fix for v in audit.vulnerabilities 
                    if v.recommended_fix}
            
            example = TrainingExample(
                contract_code=audit.contract_source.content,
                contract_name=audit.contract_name,
                vulnerability_labels=vulnerability_labels,
                severity_scores=severity_scores,
                explanations=explanations,
                fixes=fixes,
                source=audit.source_dataset or "unknown",
                is_vulnerable=True
            )
            examples.append(example)
        
        # If we have fixed versions, create negative examples
        for vuln in audit.vulnerabilities:
            if vuln.fixed_code:
                fixed_example = TrainingExample(
                    contract_code=vuln.fixed_code,
                    contract_name=f"{audit.contract_name}_fixed",
                    vulnerability_labels=[],
                    severity_scores={},
                    explanations={},
                    fixes={},
                    source=f"{audit.source_dataset}_fixed" if audit.source_dataset else "fixed",
                    is_vulnerable=False
                )
                examples.append(fixed_example)
        
        return examples
    
    @staticmethod
    def _severity_to_score(severity: SeverityLevel) -> float:
        """Convert severity level to numerical score."""
        severity_map = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2
        }
        return severity_map.get(severity, 0.0)


# JSON serialization utilities
class SchemaEncoder(json.JSONEncoder):
    """JSON encoder for schema classes."""
    
    def default(self, obj):
        if isinstance(obj, (VulnerabilityType, SeverityLevel, VulnerabilityImpact)):
            return obj.value
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)


def save_training_examples(examples: List[TrainingExample], filepath: str):
    """Save training examples to JSONL file."""
    with open(filepath, 'w') as f:
        for example in examples:
            f.write(json.dumps(example.to_dict()) + '\n')


def load_training_examples(filepath: str) -> List[TrainingExample]:
    """Load training examples from JSONL file."""
    examples = []
    with open(filepath, 'r') as f:
        for line in f:
            data = json.loads(line.strip())
            examples.append(TrainingExample.from_dict(data))
    return examples
"""
Core auditing interface for smart contract security analysis.

This module provides the main ContractAuditor class that orchestrates
vulnerability detection, severity assessment, and fix generation.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    import torch
    import torch.nn.functional as F
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel
    torch_available = True
except ImportError:
    torch_available = False
    torch = None
    F = None

from data.schema import (
    VulnerabilityType, SeverityLevel, VulnerabilityImpact,
    Vulnerability, VulnerabilityLocation, ContractAuditData, ContractSource
)

logger = logging.getLogger(__name__)


@dataclass
class AuditResult:
    """Result of a smart contract audit."""
    contract_name: str
    contract_source: str
    vulnerabilities: List[Vulnerability]
    overall_severity: SeverityLevel
    confidence_score: float
    audit_timestamp: datetime
    model_version: str
    gas_analysis: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result['audit_timestamp'] = self.audit_timestamp.isoformat()
        result['vulnerabilities'] = [asdict(v) for v in self.vulnerabilities]
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    def save_to_file(self, filepath: Union[str, Path]):
        """Save audit result to file."""
        with open(filepath, 'w') as f:
            f.write(self.to_json())


class ContractAuditor:
    """Main contract auditing interface."""
    
    def __init__(
        self,
        model_path: str,
        device: str = "auto",
        confidence_threshold: float = 0.7,
        batch_size: int = 1
    ):
        """Initialize the auditor.
        
        Args:
            model_path: Path to trained model directory
            device: Device to use ("cpu", "cuda", or "auto")
            confidence_threshold: Minimum confidence for vulnerability detection
            batch_size: Batch size for inference
        """
        self.model_path = Path(model_path)
        self.confidence_threshold = confidence_threshold
        self.batch_size = batch_size
        
        if not torch_available:
            raise ImportError("PyTorch and transformers are required for inference")
        
        # Auto-detect device
        if device == "auto":
            if torch.cuda.is_available():
                device = "cuda"
            elif torch.backends.mps.is_available():
                device = "mps"
            else:
                device = "cpu"
        
        self.device = torch.device(device)
        logger.info(f"Using device: {self.device}")
        
        # Load model and tokenizer
        self._load_model_and_tokenizer()
        
        # Vulnerability type mapping
        self.vuln_types = list(VulnerabilityType)
        self.idx_to_vuln = {i: v for i, v in enumerate(self.vuln_types)}
        
        logger.info(f"Auditor initialized with model from {model_path}")
    
    def _load_model_and_tokenizer(self):
        """Load the trained model and tokenizer."""
        try:
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            
            # Set padding token for GPT models that don't have one
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
                logger.info("Set padding token to EOS token")
            
            # Load base model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32,
                device_map={"": self.device}
            )
            
            # Check if it's a PEFT model
            peft_config_path = self.model_path / "adapter_config.json"
            if peft_config_path.exists():
                logger.info("Loading PEFT adapter...")
                self.model = PeftModel.from_pretrained(self.model, self.model_path)
            
            self.model.eval()
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def audit_contract(
        self,
        contract_code: str,
        contract_name: str = "UnknownContract",
        analyze_gas: bool = True
    ) -> AuditResult:
        """Audit a single smart contract.
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            analyze_gas: Whether to perform gas analysis
            
        Returns:
            AuditResult with detected vulnerabilities and recommendations
        """
        logger.info(f"Starting audit of contract: {contract_name}")
        
        # Tokenize input
        inputs = self.tokenizer(
            contract_code,
            return_tensors="pt",
            truncation=True,
            max_length=2048,
            padding=True
        ).to(self.device)
        
        # Run inference
        with torch.no_grad():
            # Check if model is a MultiTaskAuditModel or has forward method that returns dict
            try:
                outputs = self.model(**inputs)
                # If outputs is a dict (from MultiTaskAuditModel), use it directly
                # Otherwise, wrap it
                if not isinstance(outputs, dict):
                    # Try to get hidden states if available
                    if hasattr(outputs, 'hidden_states'):
                        outputs = {
                            'base_logits': outputs.logits if hasattr(outputs, 'logits') else None,
                            'hidden_states': outputs.hidden_states
                        }
                    else:
                        # Fallback: create dict with available outputs
                        outputs = {'base_logits': outputs.logits if hasattr(outputs, 'logits') else None}
            except Exception as e:
                logger.warning(f"Model forward pass failed: {e}, using fallback")
                # Fallback: just get logits
                outputs = self.model(**inputs)
                if hasattr(outputs, 'logits'):
                    outputs = {'base_logits': outputs.logits}
                else:
                    outputs = {}
        
        # Extract vulnerability predictions
        vulnerabilities = self._extract_vulnerabilities(
            outputs, contract_code, contract_name
        )
        
        # Determine overall severity
        overall_severity = self._determine_overall_severity(vulnerabilities)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence(vulnerabilities)
        
        # Perform gas analysis if requested
        gas_analysis = None
        if analyze_gas:
            gas_analysis = self._analyze_gas_usage(contract_code)
        
        # Create audit result
        result = AuditResult(
            contract_name=contract_name,
            contract_source=contract_code,
            vulnerabilities=vulnerabilities,
            overall_severity=overall_severity,
            confidence_score=confidence_score,
            audit_timestamp=datetime.now(),
            model_version=str(self.model_path.name),
            gas_analysis=gas_analysis
        )
        
        logger.info(f"Audit completed: {len(vulnerabilities)} vulnerabilities found")
        return result
    
    def audit_file(self, filepath: Union[str, Path]) -> AuditResult:
        """Audit a contract from a file.
        
        Args:
            filepath: Path to Solidity file
            
        Returns:
            AuditResult
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Contract file not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            contract_code = f.read()
        
        contract_name = filepath.stem
        return self.audit_contract(contract_code, contract_name)
    
    def batch_audit(
        self,
        contracts: List[Tuple[str, str]],  # (code, name) pairs
        progress_callback: Optional[callable] = None
    ) -> List[AuditResult]:
        """Audit multiple contracts in batch.
        
        Args:
            contracts: List of (contract_code, contract_name) tuples
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of AuditResults
        """
        results = []
        
        for i, (contract_code, contract_name) in enumerate(contracts):
            try:
                result = self.audit_contract(contract_code, contract_name)
                results.append(result)
                
                if progress_callback:
                    progress_callback(i + 1, len(contracts), contract_name)
                    
            except Exception as e:
                logger.error(f"Failed to audit {contract_name}: {e}")
                # Create error result
                error_result = AuditResult(
                    contract_name=contract_name,
                    contract_source=contract_code,
                    vulnerabilities=[],
                    overall_severity=SeverityLevel.INFO,
                    confidence_score=0.0,
                    audit_timestamp=datetime.now(),
                    model_version=str(self.model_path.name)
                )
                results.append(error_result)
        
        return results
    
    def _extract_vulnerabilities(
        self,
        model_outputs,
        contract_code: str,
        contract_name: str
    ) -> List[Vulnerability]:
        """Extract vulnerability predictions from model outputs using neural network."""
        vulnerabilities = []
        
        # Check if model has multi-task outputs (trained model)
        if hasattr(model_outputs, 'vulnerability_logits') or isinstance(model_outputs, dict):
            # Use neural network model predictions
            if isinstance(model_outputs, dict):
                vuln_logits = model_outputs.get('vulnerability_logits')
                severity_preds = model_outputs.get('severity_predictions')
                detection_logits = model_outputs.get('detection_logits')
            else:
                vuln_logits = model_outputs.vulnerability_logits
                severity_preds = model_outputs.severity_predictions
                detection_logits = model_outputs.detection_logits
            
            # Check if contract is vulnerable
            if detection_logits is not None:
                if F is None:
                    import torch.nn.functional as F
                detection_prob = torch.sigmoid(detection_logits.squeeze())
                if detection_prob.item() < self.confidence_threshold:
                    # Model says contract is not vulnerable
                    return []
            
            # Extract vulnerability predictions from logits
            if vuln_logits is not None:
                if F is None:
                    import torch.nn.functional as F
                vuln_probs = torch.sigmoid(vuln_logits.squeeze())
                
                # Get predicted vulnerability types
                predicted_indices = (vuln_probs > self.confidence_threshold).nonzero(as_tuple=True)[0]
                
                for idx in predicted_indices:
                    vuln_type = self.idx_to_vuln.get(idx.item())
                    if vuln_type is None:
                        continue
                    
                    confidence = vuln_probs[idx].item()
                    
                    # Get severity prediction
                    if severity_preds is not None:
                        severity_score = severity_preds.squeeze()[idx].item()
                        severity = self._score_to_severity(severity_score)
                    else:
                        severity = self._estimate_severity(vuln_type, contract_code)
                    
                    # Find location in code
                    location = self._find_vulnerability_location_in_code(contract_code, vuln_type)
                    
                    vulnerability = Vulnerability(
                        vulnerability_type=vuln_type,
                        severity=severity,
                        impact=self._determine_impact(vuln_type),
                        location=location,
                        affected_code=self._extract_affected_code(contract_code, location),
                        title=self._get_vulnerability_title(vuln_type),
                        description=self._get_vulnerability_description(vuln_type),
                        root_cause=self._get_root_cause(vuln_type),
                        recommended_fix=self._get_recommended_fix(vuln_type),
                        confidence=confidence
                    )
                    vulnerabilities.append(vulnerability)
            
            return vulnerabilities
        
        # Fallback: If model doesn't have expected outputs, use pattern matching
        # This handles cases where model structure is different or model isn't fully trained
        logger.warning("Model outputs don't match expected format, using pattern matching fallback")
        return self._extract_vulnerabilities_pattern_based(contract_code, contract_name)
    
    def _extract_vulnerabilities_pattern_based(
        self,
        contract_code: str,
        contract_name: str
    ) -> List[Vulnerability]:
        """Pattern-based fallback vulnerability detection."""
        vulnerabilities = []
        patterns = {
            VulnerabilityType.REENTRANCY: [
                r'\.call\{value:.*\}\(\)',
                r'\.call\(.*\)',
                r'transfer\(.*\)',
                r'send\(.*\)'
            ],
            VulnerabilityType.ACCESS_CONTROL: [
                r'tx\.origin',
                r'onlyOwner',
                r'msg\.sender\s*==\s*owner'
            ],
            VulnerabilityType.INTEGER_OVERFLOW: [
                r'\+\+',
                r'--',
                r'\+=',
                r'-=',
                r'\*=',
                r'/='
            ],
            VulnerabilityType.UNCHECKED_CALL: [
                r'\.call\(',
                r'\.delegatecall\(',
                r'\.staticcall\('
            ]
        }
        
        lines = contract_code.split('\n')
        import re
        
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerability = Vulnerability(
                            vulnerability_type=vuln_type,
                            severity=self._estimate_severity(vuln_type, line),
                            impact=self._determine_impact(vuln_type),
                            location=VulnerabilityLocation(
                                line_start=line_num,
                                line_end=line_num,
                                contract_name=contract_name
                            ),
                            affected_code=line.strip(),
                            title=self._get_vulnerability_title(vuln_type),
                            description=self._get_vulnerability_description(vuln_type),
                            root_cause=self._get_root_cause(vuln_type),
                            recommended_fix=self._get_recommended_fix(vuln_type),
                            confidence=0.6  # Lower confidence for pattern matching
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convert severity score (0.0-1.0) to SeverityLevel."""
        if score >= 0.9:
            return SeverityLevel.CRITICAL
        elif score >= 0.7:
            return SeverityLevel.HIGH
        elif score >= 0.5:
            return SeverityLevel.MEDIUM
        elif score >= 0.3:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _find_vulnerability_location_in_code(
        self,
        contract_code: str,
        vuln_type: VulnerabilityType
    ) -> VulnerabilityLocation:
        """Find approximate location of vulnerability in code."""
        lines = contract_code.split('\n')
        import re
        
        # Pattern hints for each vulnerability type
        patterns = {
            VulnerabilityType.REENTRANCY: [r'\.call\{value:', r'\.call\(', r'\.transfer\('],
            VulnerabilityType.TX_ORIGIN: [r'tx\.origin'],
            VulnerabilityType.TIMESTAMP_DEPENDENCE: [r'block\.timestamp', r'\bnow\b'],
            VulnerabilityType.UNCHECKED_CALL: [r'\.call\(', r'\.delegatecall\('],
        }
        
        for pattern in patterns.get(vuln_type, []):
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    return VulnerabilityLocation(
                        line_start=line_num,
                        line_end=line_num,
                        contract_name="Contract"
                    )
        
        # Default to first line if not found
        return VulnerabilityLocation(line_start=1, line_end=1, contract_name="Contract")
    
    def _extract_affected_code(self, contract_code: str, location: VulnerabilityLocation) -> str:
        """Extract affected code snippet around vulnerability location."""
        lines = contract_code.split('\n')
        start = max(0, location.line_start - 2)
        end = min(len(lines), location.line_end + 2)
        return '\n'.join(lines[start:end])
    
    def _estimate_severity(self, vuln_type: VulnerabilityType, code_line: str) -> SeverityLevel:
        """Estimate severity based on vulnerability type and context."""
        severity_map = {
            VulnerabilityType.REENTRANCY: SeverityLevel.CRITICAL,
            VulnerabilityType.ACCESS_CONTROL: SeverityLevel.HIGH,
            VulnerabilityType.INTEGER_OVERFLOW: SeverityLevel.HIGH,
            VulnerabilityType.UNCHECKED_CALL: SeverityLevel.MEDIUM,
        }
        return severity_map.get(vuln_type, SeverityLevel.LOW)
    
    def _determine_impact(self, vuln_type: VulnerabilityType) -> List[VulnerabilityImpact]:
        """Determine potential impact of vulnerability type."""
        impact_map = {
            VulnerabilityType.REENTRANCY: [VulnerabilityImpact.FUNDS_LOSS],
            VulnerabilityType.ACCESS_CONTROL: [VulnerabilityImpact.FUNDS_LOSS, VulnerabilityImpact.GOVERNANCE],
            VulnerabilityType.INTEGER_OVERFLOW: [VulnerabilityImpact.FUNDS_LOSS],
            VulnerabilityType.UNCHECKED_CALL: [VulnerabilityImpact.DOS],
        }
        return impact_map.get(vuln_type, [VulnerabilityImpact.CODE_QUALITY])
    
    def _get_vulnerability_title(self, vuln_type: VulnerabilityType) -> str:
        """Get human-readable title for vulnerability type."""
        titles = {
            VulnerabilityType.REENTRANCY: "Reentrancy Vulnerability",
            VulnerabilityType.ACCESS_CONTROL: "Access Control Issue",
            VulnerabilityType.INTEGER_OVERFLOW: "Integer Overflow/Underflow",
            VulnerabilityType.UNCHECKED_CALL: "Unchecked External Call",
        }
        return titles.get(vuln_type, str(vuln_type.value))
    
    def _get_vulnerability_description(self, vuln_type: VulnerabilityType) -> str:
        """Get detailed description for vulnerability type."""
        descriptions = {
            VulnerabilityType.REENTRANCY: "External calls are made before state changes, allowing for reentrancy attacks.",
            VulnerabilityType.ACCESS_CONTROL: "Access control mechanisms are insufficient or incorrectly implemented.",
            VulnerabilityType.INTEGER_OVERFLOW: "Arithmetic operations may overflow or underflow without proper checks.",
            VulnerabilityType.UNCHECKED_CALL: "Return values of external calls are not properly checked.",
        }
        return descriptions.get(vuln_type, "Potential security vulnerability detected.")
    
    def _get_root_cause(self, vuln_type: VulnerabilityType) -> str:
        """Get root cause explanation for vulnerability type."""
        causes = {
            VulnerabilityType.REENTRANCY: "Violation of checks-effects-interactions pattern",
            VulnerabilityType.ACCESS_CONTROL: "Insufficient access control validation",
            VulnerabilityType.INTEGER_OVERFLOW: "Missing SafeMath or overflow protection",
            VulnerabilityType.UNCHECKED_CALL: "Unchecked return values from external calls",
        }
        return causes.get(vuln_type, "Security best practices not followed.")
    
    def _get_recommended_fix(self, vuln_type: VulnerabilityType) -> str:
        """Get recommended fix for vulnerability type."""
        fixes = {
            VulnerabilityType.REENTRANCY: "Follow checks-effects-interactions pattern: update state before external calls",
            VulnerabilityType.ACCESS_CONTROL: "Implement proper access control modifiers and use msg.sender instead of tx.origin",
            VulnerabilityType.INTEGER_OVERFLOW: "Use SafeMath library or Solidity ^0.8.0 with built-in overflow checks",
            VulnerabilityType.UNCHECKED_CALL: "Check return values of external calls and handle failures appropriately",
        }
        return fixes.get(vuln_type, "Follow security best practices and conduct thorough testing.")
    
    def _determine_overall_severity(self, vulnerabilities: List[Vulnerability]) -> SeverityLevel:
        """Determine overall severity from individual vulnerabilities."""
        if not vulnerabilities:
            return SeverityLevel.INFO
        
        severities = [v.severity for v in vulnerabilities]
        
        if SeverityLevel.CRITICAL in severities:
            return SeverityLevel.CRITICAL
        elif SeverityLevel.HIGH in severities:
            return SeverityLevel.HIGH
        elif SeverityLevel.MEDIUM in severities:
            return SeverityLevel.MEDIUM
        elif SeverityLevel.LOW in severities:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _calculate_confidence(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall confidence score."""
        if not vulnerabilities:
            return 1.0  # High confidence in finding no vulnerabilities
        
        confidences = [v.confidence for v in vulnerabilities]
        return sum(confidences) / len(confidences)
    
    def _analyze_gas_usage(self, contract_code: str) -> Dict:
        """Analyze gas usage patterns (placeholder implementation)."""
        # This would integrate with Solidity compiler or gas analysis tools
        return {
            "estimated_deployment_gas": 0,
            "high_gas_functions": [],
            "optimization_suggestions": []
        }
    
    def generate_report(self, result: AuditResult, format: str = "markdown") -> str:
        """Generate a formatted audit report.
        
        Args:
            result: AuditResult to format
            format: Output format ("markdown", "html", "txt")
            
        Returns:
            Formatted report string
        """
        if format.lower() == "markdown":
            return self._generate_markdown_report(result)
        elif format.lower() == "html":
            return self._generate_html_report(result)
        else:
            return self._generate_text_report(result)
    
    def _generate_markdown_report(self, result: AuditResult) -> str:
        """Generate Markdown formatted report."""
        report_lines = [
            f"# Smart Contract Audit Report",
            f"",
            f"**Contract:** {result.contract_name}",
            f"**Audit Date:** {result.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Model Version:** {result.model_version}",
            f"**Overall Severity:** {result.overall_severity.value.upper()}",
            f"**Confidence Score:** {result.confidence_score:.2f}",
            f"",
            f"## Executive Summary",
            f"",
            f"Total vulnerabilities found: **{len(result.vulnerabilities)}**",
            f""
        ]
        
        if result.vulnerabilities:
            # Group by severity
            severity_groups = {}
            for vuln in result.vulnerabilities:
                severity = vuln.severity
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(vuln)
            
            report_lines.extend([
                f"### Vulnerability Summary",
                f""
            ])
            
            for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
                if severity in severity_groups:
                    count = len(severity_groups[severity])
                    report_lines.append(f"- **{severity.value.title()}:** {count}")
            
            report_lines.extend([
                f"",
                f"## Detailed Findings",
                f""
            ])
            
            for i, vuln in enumerate(result.vulnerabilities, 1):
                report_lines.extend([
                    f"### {i}. {vuln.title}",
                    f"",
                    f"**Severity:** {vuln.severity.value.upper()}",
                    f"**Confidence:** {vuln.confidence:.2f}",
                    f"**Location:** Line {vuln.location.line_start}",
                    f"",
                    f"**Description:**",
                    f"{vuln.description}",
                    f"",
                    f"**Root Cause:**",
                    f"{vuln.root_cause}",
                    f"",
                    f"**Affected Code:**",
                    f"```solidity",
                    f"{vuln.affected_code}",
                    f"```",
                    f"",
                    f"**Recommended Fix:**",
                    f"{vuln.recommended_fix}",
                    f"",
                    f"---",
                    f""
                ])
        else:
            report_lines.extend([
                f"✅ No vulnerabilities detected.",
                f"",
                f"The contract appears to follow security best practices. However, this automated analysis should be supplemented with manual review and comprehensive testing.",
                f""
            ])
        
        report_lines.extend([
            f"## Disclaimer",
            f"",
            f"This audit report is generated by an AI model and should be used as a starting point for security analysis. ",
            f"Always conduct thorough manual reviews and testing before deploying smart contracts to production.",
            f""
        ])
        
        return "\n".join(report_lines)
    
    def _generate_html_report(self, result: AuditResult) -> str:
        """Generate HTML formatted report."""
        # Convert markdown to HTML (simplified)
        markdown_report = self._generate_markdown_report(result)
        # In a real implementation, you'd use a proper markdown to HTML converter
        html_report = f"<pre>{markdown_report}</pre>"
        return html_report
    
    def _generate_text_report(self, result: AuditResult) -> str:
        """Generate plain text report."""
        markdown_report = self._generate_markdown_report(result)
        # Remove markdown formatting
        import re
        text_report = re.sub(r'[#*`-]', '', markdown_report)
        return text_report
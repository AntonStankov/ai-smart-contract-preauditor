#!/usr/bin/env python3
"""
Neural Network-Based Contract Auditor

This auditor uses the actual trained neural network model instead of pattern matching.
It learns from forum discussions, web searches, and security research to detect vulnerabilities.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from auditor.core import ContractAuditor, AuditResult
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NeuralContractAuditor:
    """
    Contract auditor that uses a trained neural network model.
    
    The model learns from:
    - Reddit security discussions
    - Web search results
    - GitHub security research
    - SWC registry examples
    - Forum discussions about vulnerabilities
    """
    
    def __init__(self, model_path: str = None):
        """
        Initialize the neural network auditor.
        
        Args:
            model_path: Path to trained model. If None, tries to find latest checkpoint.
        """
        if model_path is None:
            # Try to find the latest trained model
            checkpoint_dir = Path("checkpoints")
            possible_paths = [
                checkpoint_dir / "forum-trained-model",
                checkpoint_dir / "simple-enhanced-model",
                checkpoint_dir / "simple-enhanced-model" / "checkpoint-33",
            ]
            
            for path in possible_paths:
                if path.exists() and (path / "model.safetensors").exists():
                    model_path = str(path)
                    logger.info(f"Found model at: {model_path}")
                    break
        
        if model_path is None:
            raise FileNotFoundError(
                "No trained model found. Please train a model first using:\n"
                "  python train_with_forum_data.py"
            )
        
        # Initialize the core auditor with the trained model
        self.auditor = ContractAuditor(
            model_path=model_path,
            device="auto",
            confidence_threshold=0.7
        )
        
        self.model_version = Path(model_path).name
        logger.info(f"Neural network auditor initialized with model: {self.model_version}")
    
    def audit_contract(self, contract_code: str, contract_name: str = "Contract") -> AuditResult:
        """
        Audit a contract using the neural network model.
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            
        Returns:
            AuditResult with detected vulnerabilities
        """
        logger.info(f"Auditing contract '{contract_name}' using neural network model...")
        
        # Use the core auditor which now uses the neural network
        result = self.auditor.audit_contract(contract_code, contract_name)
        
        logger.info(f"Audit complete: {len(result.vulnerabilities)} vulnerabilities found")
        
        return result
    
    def audit_file(self, filepath: str) -> AuditResult:
        """Audit a contract from a file."""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Contract file not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            contract_code = f.read()
        
        contract_name = filepath.stem
        return self.audit_contract(contract_code, contract_name)
    
    def generate_report(self, result: AuditResult, format: str = "markdown") -> str:
        """Generate an audit report."""
        return self.auditor.generate_report(result, format)


def main():
    """Main entry point for neural network auditor."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Audit smart contracts using neural network model trained on forum data"
    )
    parser.add_argument(
        "contract_file",
        help="Path to Solidity contract file to audit"
    )
    parser.add_argument(
        "--model",
        help="Path to trained model (auto-detected if not specified)"
    )
    parser.add_argument(
        "--output",
        help="Output file for audit report (default: audit_report_<contract_name>.md)"
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "html", "json"],
        default="markdown",
        help="Report format"
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize auditor
        print("🤖 Initializing Neural Network Auditor...")
        print("   Model learns from: Reddit, forums, web searches, security research")
        print()
        
        auditor = NeuralContractAuditor(model_path=args.model)
        
        # Perform audit
        print(f"🔍 Auditing: {Path(args.contract_file).name}")
        result = auditor.audit_file(args.contract_file)
        
        # Generate report
        report = auditor.generate_report(result, args.format)
        
        # Save report
        if args.output:
            output_file = Path(args.output)
        else:
            contract_name = Path(args.contract_file).stem
            output_file = Path(f"audit_report_{contract_name}.md")
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(report)
        
        # Print summary
        print()
        print("=" * 60)
        print("AUDIT SUMMARY")
        print("=" * 60)
        print(f"Contract: {result.contract_name}")
        print(f"Model: {auditor.model_version}")
        print(f"Overall Severity: {result.overall_severity.value.upper()}")
        print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
        print(f"Confidence Score: {result.confidence_score:.1%}")
        print()
        
        if result.vulnerabilities:
            print("Detected Vulnerabilities:")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢',
                    'info': 'ℹ️'
                }
                emoji = severity_emoji.get(vuln.severity.value, '⚪')
                print(f"  {i}. {emoji} {vuln.title} ({vuln.severity.value.upper()})")
                print(f"     Confidence: {vuln.confidence:.1%}")
                print(f"     Location: Line {vuln.location.line_start}")
        else:
            print("✅ No vulnerabilities detected")
        
        print()
        print(f"📄 Full report saved to: {output_file}")
        print("=" * 60)
        
        return 0
        
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        print()
        print("To train a model, run:")
        print("  python train_with_forum_data.py")
        return 1
    except Exception as e:
        print(f"❌ Error during audit: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())




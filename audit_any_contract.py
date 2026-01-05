#!/usr/bin/env python3
"""
Simple script to audit any contract file using the internet-trained demo auditor.
Usage: python audit_any_contract.py <contract_file>
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.append('/home/antonstankov/contract-ai-auditor')

from datetime import datetime

# Try to use neural network auditor first, fallback to pattern matching
try:
    from neural_auditor import NeuralContractAuditor
    USE_NEURAL_NETWORK = True
except (ImportError, FileNotFoundError):
    USE_NEURAL_NETWORK = False
    from demo_internet_auditor import InternetTrainedAuditor

def audit_contract(contract_file: str):
    """Audit a specific contract file."""
    
    contract_path = Path(contract_file)
    
    # Check if file exists
    if not contract_path.exists():
        print(f"❌ Contract file not found: {contract_file}")
        return 1
    
    # Read contract
    try:
        with open(contract_path, 'r') as f:
            contract_code = f.read()
    except Exception as e:
        print(f"❌ Failed to read contract: {e}")
        return 1
    
    print(f"🔍 Auditing: {contract_path.name}")
    print(f"📦 Size: {len(contract_code)} characters")
    print()
    
    # Initialize auditor and perform audit
    if USE_NEURAL_NETWORK:
        try:
            print("🤖 Using Neural Network Model (learned from forums & web searches)")
            auditor = NeuralContractAuditor()
            result = auditor.audit_contract(contract_code, contract_path.stem)
            generate_report = auditor.generate_report
        except FileNotFoundError:
            print("⚠️  Neural network model not found, using pattern matching fallback")
            print("   Train a model with: python train_with_forum_data.py")
            USE_NEURAL_NETWORK = False
    
    if not USE_NEURAL_NETWORK:
        print("🔍 Using Pattern Matching (limited capabilities)")
        auditor = InternetTrainedAuditor()
        result = auditor.audit_contract(contract_code, contract_path.stem)
        generate_report = auditor.generate_report
    
    # Generate report
    report = generate_report(result, "markdown")
    
    # Save report
    output_file = contract_path.parent / f"audit_report_{contract_path.stem}.md"
    with open(output_file, 'w') as f:
        f.write(report)
    
    # Print summary
    print("=== AUDIT SUMMARY ===")
    print(f"Contract: {result.contract_name}")
    print(f"Overall Severity: {result.overall_severity.value.upper()}")
    print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
    print(f"Confidence Score: {result.confidence_score:.1%}")
    print()
    
    if result.vulnerabilities:
        print("Detected Vulnerabilities:")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
            emoji = severity_emoji.get(vuln.severity.value, '⚪')
            print(f"  {i}. {emoji} {vuln.title} ({vuln.severity.value.upper()})")
    else:
        print("✅ No vulnerabilities detected")
    
    print()
    print(f"📄 Full report saved to: {output_file}")
    
    return 0

def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python audit_any_contract.py <contract_file>")
        print()
        print("Examples:")
        print("  python audit_any_contract.py contracts/vulnerable/reentrancy_victim.sol")
        print("  python audit_any_contract.py /path/to/your/contract.sol")
        print()
        print("Available test contracts:")
        vulnerable_dir = Path("/home/antonstankov/contract-ai-auditor/contracts/vulnerable")
        if vulnerable_dir.exists():
            for contract in vulnerable_dir.glob("*.sol"):
                print(f"  - {contract}")
        return 1
    
    contract_file = sys.argv[1]
    return audit_contract(contract_file)

if __name__ == "__main__":
    sys.exit(main())
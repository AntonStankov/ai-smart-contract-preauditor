#!/usr/bin/env python3
"""
Command-line interface for Contract AI Auditor.

This script provides an easy-to-use CLI for auditing smart contracts.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from auditor.core import ContractAuditor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def audit_single_contract(args):
    """Audit a single contract file."""
    try:
        # Initialize auditor
        auditor = ContractAuditor(
            model_path=args.model_path,
            device=args.device,
            confidence_threshold=args.confidence_threshold
        )
        
        # Audit the contract
        result = auditor.audit_file(args.contract_file)
        
        # Generate report
        if args.output_format:
            report = auditor.generate_report(result, args.output_format)
            
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    f.write(report)
                logger.info(f"Report saved to {args.output_file}")
            else:
                print(report)
        
        # Save JSON result if requested
        if args.json_output:
            result.save_to_file(args.json_output)
            logger.info(f"JSON result saved to {args.json_output}")
        
        # Print summary
        print(f"\n✓ Audit completed for {result.contract_name}")
        print(f"Overall Severity: {result.overall_severity.value.upper()}")
        print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
        print(f"Confidence Score: {result.confidence_score:.2f}")
        
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        return 1
    
    return 0


def audit_multiple_contracts(args):
    """Audit multiple contract files."""
    try:
        # Initialize auditor
        auditor = ContractAuditor(
            model_path=args.model_path,
            device=args.device,
            confidence_threshold=args.confidence_threshold
        )
        
        # Collect contract files
        contract_files = []
        for pattern in args.contract_files:
            path = Path(pattern)
            if path.is_file():
                contract_files.append(path)
            elif path.is_dir():
                # Find all .sol files in directory
                contract_files.extend(path.glob("**/*.sol"))
            else:
                # Try as glob pattern
                contract_files.extend(Path(".").glob(pattern))
        
        if not contract_files:
            logger.error("No contract files found!")
            return 1
        
        logger.info(f"Found {len(contract_files)} contract files")
        
        # Prepare contracts for batch audit
        contracts = []
        for file_path in contract_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                contracts.append((code, file_path.stem))
            except Exception as e:
                logger.warning(f"Failed to read {file_path}: {e}")
        
        # Progress callback
        def progress_callback(current, total, contract_name):
            percent = (current / total) * 100
            print(f"Progress: {current}/{total} ({percent:.1f}%) - {contract_name}")
        
        # Batch audit
        results = auditor.batch_audit(contracts, progress_callback)
        
        # Generate summary report
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        critical_count = sum(1 for r in results if r.overall_severity.value == 'critical')
        high_count = sum(1 for r in results if r.overall_severity.value == 'high')
        
        print(f"\n" + "="*60)
        print(f"BATCH AUDIT SUMMARY")
        print(f"="*60)
        print(f"Contracts Audited: {len(results)}")
        print(f"Total Vulnerabilities: {total_vulns}")
        print(f"Critical Issues: {critical_count}")
        print(f"High Issues: {high_count}")
        
        # Save individual results
        if args.output_dir:
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            for i, (result, file_path) in enumerate(zip(results, contract_files)):
                # Save JSON
                json_file = output_dir / f"{result.contract_name}_audit.json"
                result.save_to_file(json_file)
                
                # Save report
                if args.output_format:
                    report = auditor.generate_report(result, args.output_format)
                    ext = "md" if args.output_format == "markdown" else args.output_format
                    report_file = output_dir / f"{result.contract_name}_report.{ext}"
                    with open(report_file, 'w') as f:
                        f.write(report)
            
            logger.info(f"Results saved to {output_dir}")
        
    except Exception as e:
        logger.error(f"Batch audit failed: {e}")
        return 1
    
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Smart Contract AI Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit a single contract
  audit-contract --model-path ./models/auditor --contract-file contract.sol
  
  # Audit multiple contracts with output
  audit-contract --model-path ./models/auditor --contract-files "contracts/*.sol" --output-dir ./audit_results
  
  # Generate markdown report
  audit-contract --model-path ./models/auditor --contract-file contract.sol --output-format markdown --output-file report.md
        """
    )
    
    # Global arguments
    parser.add_argument(
        "--model-path",
        default="distilgpt2",  # Default to base model if no fine-tuned model is available
        help="Path to trained auditor model or model name (default: distilgpt2)"
    )
    parser.add_argument(
        "--device",
        default="auto",
        choices=["auto", "cpu", "cuda", "mps"],
        help="Device to use for inference"
    )
    parser.add_argument(
        "--confidence-threshold",
        type=float,
        default=0.7,
        help="Minimum confidence threshold for reporting vulnerabilities"
    )
    parser.add_argument(
        "--output-format",
        choices=["markdown", "html", "txt"],
        help="Output report format"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Single contract audit
    single_parser = subparsers.add_parser("single", help="Audit a single contract")
    single_parser.add_argument(
        "contract_file",
        help="Path to Solidity contract file"
    )
    single_parser.add_argument(
        "--output-file", "-o",
        help="Output file for report"
    )
    single_parser.add_argument(
        "--json-output",
        help="Save JSON audit result to file"
    )
    
    # Multiple contract audit  
    batch_parser = subparsers.add_parser("batch", help="Audit multiple contracts")
    batch_parser.add_argument(
        "contract_files",
        nargs="+",
        help="Contract files or directories (supports glob patterns)"
    )
    batch_parser.add_argument(
        "--output-dir",
        help="Output directory for reports and results"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check if model path exists (skip validation for model names like 'distilgpt2')
    model_path = Path(args.model_path)
    if "/" in args.model_path and not model_path.exists():
        logger.error(f"Model path does not exist: {model_path}")
        return 1
    
    # Backward compatibility - if no subcommand and contract_file is provided
    if not args.command:
        if len(sys.argv) > 1 and Path(sys.argv[-1]).suffix == '.sol':
            # Assume single contract audit
            args.command = "single"
            args.contract_file = sys.argv[-1]
            args.output_file = None
            args.json_output = None
        else:
            parser.print_help()
            return 1
    
    # Execute command
    if args.command == "single":
        return audit_single_contract(args)
    elif args.command == "batch":
        return audit_multiple_contracts(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
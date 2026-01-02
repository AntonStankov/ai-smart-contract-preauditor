#!/usr/bin/env python3
"""
Evaluation script for Contract AI Auditor models.

This script evaluates trained models on test datasets and generates
comprehensive performance reports.
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from auditor.core import ContractAuditor
from evaluation.evaluator import ModelEvaluator
from data.schema import load_training_examples

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Evaluate Contract AI Auditor model")
    parser.add_argument(
        "--model-path",
        required=True,
        help="Path to trained model directory"
    )
    parser.add_argument(
        "--test-data",
        default="data/splits/test.jsonl",
        help="Path to test dataset"
    )
    parser.add_argument(
        "--results-dir",
        default="evaluation/reports",
        help="Directory to save evaluation results"
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
        help="Minimum confidence threshold for predictions"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Batch size for evaluation"
    )
    
    args = parser.parse_args()
    
    # Validate paths
    model_path = Path(args.model_path)
    if not model_path.exists():
        logger.error(f"Model path does not exist: {model_path}")
        return 1
    
    test_data_path = Path(args.test_data)
    if not test_data_path.exists():
        logger.error(f"Test data path does not exist: {test_data_path}")
        return 1
    
    # Load test data
    logger.info(f"Loading test data from {test_data_path}")
    test_examples = load_training_examples(str(test_data_path))
    
    if not test_examples:
        logger.error("No test examples found!")
        return 1
    
    logger.info(f"Loaded {len(test_examples)} test examples")
    
    # Initialize auditor
    logger.info("Initializing auditor...")
    try:
        auditor = ContractAuditor(
            model_path=str(model_path),
            device=args.device,
            confidence_threshold=args.confidence_threshold,
            batch_size=args.batch_size
        )
    except Exception as e:
        logger.error(f"Failed to initialize auditor: {e}")
        return 1
    
    # Initialize evaluator
    evaluator = ModelEvaluator(auditor)
    
    # Run evaluation
    logger.info("Starting model evaluation...")
    try:
        results = evaluator.evaluate_model(
            test_examples=test_examples,
            save_results=True,
            results_dir=args.results_dir
        )
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        return 1
    
    # Print summary
    print("\n" + "="*60)
    print("EVALUATION SUMMARY")
    print("="*60)
    print(f"Total Contracts Evaluated: {results.total_contracts_evaluated}")
    print(f"Evaluation Time: {results.evaluation_time:.2f} seconds")
    print(f"False Positive Rate: {results.false_positive_rate:.3f}")
    print(f"False Negative Rate: {results.false_negative_rate:.3f}")
    
    # Vulnerability detection summary
    print("\nVulnerability Detection Performance:")
    print("-" * 40)
    
    macro_precision = []
    macro_recall = []
    macro_f1 = []
    
    for vuln_type, metrics in results.vulnerability_detection.items():
        print(f"{vuln_type:20s} P:{metrics.precision:.3f} R:{metrics.recall:.3f} F1:{metrics.f1_score:.3f}")
        macro_precision.append(metrics.precision)
        macro_recall.append(metrics.recall)
        macro_f1.append(metrics.f1_score)
    
    if macro_f1:
        print(f"{'MACRO AVERAGE':20s} P:{sum(macro_precision)/len(macro_precision):.3f} "
              f"R:{sum(macro_recall)/len(macro_recall):.3f} "
              f"F1:{sum(macro_f1)/len(macro_f1):.3f}")
    
    # Severity assessment summary
    print(f"\nSeverity Assessment:")
    print(f"RMSE: {results.severity_assessment.rmse:.4f}")
    print(f"Correlation: {results.severity_assessment.correlation:.4f}")
    
    # Fix generation summary
    print(f"\nFix Generation:")
    print(f"BLEU Score: {results.fix_generation.bleu_score:.4f}")
    print(f"ROUGE-1: {results.fix_generation.rouge_1:.4f}")
    
    # Precision at K
    if results.precision_at_k:
        print(f"\nPrecision at K:")
        for k, precision in results.precision_at_k.items():
            print(f"P@{k}: {precision:.3f}")
    
    print("\n" + "="*60)
    logger.info(f"Evaluation completed! Results saved to {args.results_dir}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
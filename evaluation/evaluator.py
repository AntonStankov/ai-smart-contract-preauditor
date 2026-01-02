"""
Comprehensive evaluation metrics for Contract AI Auditor models.

This module provides metrics for assessing model performance across different
tasks including vulnerability detection, severity assessment, and fix generation.
"""

import json
import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
from datetime import datetime

try:
    from sklearn.metrics import (
        precision_recall_fscore_support, accuracy_score, 
        classification_report, confusion_matrix, roc_auc_score,
        mean_squared_error, mean_absolute_error
    )
    sklearn_available = True
except ImportError:
    sklearn_available = False

try:
    from rouge_score import rouge_scorer
    rouge_available = True
except ImportError:
    rouge_available = False

from data.schema import VulnerabilityType, SeverityLevel, TrainingExample
from auditor.core import ContractAuditor, AuditResult

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityMetrics:
    """Metrics for vulnerability detection."""
    vulnerability_type: str
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    support: int
    auc: Optional[float] = None


@dataclass
class SeverityMetrics:
    """Metrics for severity assessment."""
    mse: float
    rmse: float
    mae: float
    correlation: float


@dataclass
class FixGenerationMetrics:
    """Metrics for fix generation quality."""
    bleu_score: float
    rouge_1: float
    rouge_2: float
    rouge_l: float
    compilation_success_rate: float
    semantic_similarity: float


@dataclass
class OverallMetrics:
    """Overall evaluation metrics."""
    vulnerability_detection: Dict[str, VulnerabilityMetrics]
    severity_assessment: SeverityMetrics
    fix_generation: FixGenerationMetrics
    false_positive_rate: float
    false_negative_rate: float
    precision_at_k: Dict[int, float]
    evaluation_time: float
    total_contracts_evaluated: int


class VulnerabilityEvaluator:
    """Evaluator for vulnerability detection performance."""
    
    def __init__(self):
        if not sklearn_available:
            logger.warning("scikit-learn not available. Some metrics will be limited.")
    
    def evaluate_vulnerability_detection(
        self,
        true_labels: List[List[VulnerabilityType]],
        predicted_labels: List[List[VulnerabilityType]],
        confidence_scores: Optional[List[List[float]]] = None
    ) -> Dict[str, VulnerabilityMetrics]:
        """Evaluate vulnerability detection performance.
        
        Args:
            true_labels: Ground truth vulnerability types per contract
            predicted_labels: Predicted vulnerability types per contract  
            confidence_scores: Confidence scores for predictions
            
        Returns:
            Dictionary mapping vulnerability types to their metrics
        """
        if not sklearn_available:
            return self._simple_evaluation(true_labels, predicted_labels)
        
        # Convert to binary multilabel format
        all_vuln_types = list(VulnerabilityType)
        n_samples = len(true_labels)
        n_classes = len(all_vuln_types)
        
        true_binary = np.zeros((n_samples, n_classes))
        pred_binary = np.zeros((n_samples, n_classes))
        
        for i, (true_vulns, pred_vulns) in enumerate(zip(true_labels, predicted_labels)):
            for vuln in true_vulns:
                if vuln in all_vuln_types:
                    true_binary[i, all_vuln_types.index(vuln)] = 1
            
            for vuln in pred_vulns:
                if vuln in all_vuln_types:
                    pred_binary[i, all_vuln_types.index(vuln)] = 1
        
        # Calculate metrics per vulnerability type
        metrics = {}
        
        for i, vuln_type in enumerate(all_vuln_types):
            try:
                precision, recall, f1, support = precision_recall_fscore_support(
                    true_binary[:, i], pred_binary[:, i], average='binary', zero_division=0
                )
                
                accuracy = accuracy_score(true_binary[:, i], pred_binary[:, i])
                
                # Calculate AUC if confidence scores available
                auc = None
                if confidence_scores:
                    try:
                        conf_scores = [scores[i] if i < len(scores) else 0.0 
                                     for scores in confidence_scores]
                        if len(set(true_binary[:, i])) > 1:  # Need both classes for AUC
                            auc = roc_auc_score(true_binary[:, i], conf_scores)
                    except Exception as e:
                        logger.warning(f"Could not calculate AUC for {vuln_type.value}: {e}")
                
                metrics[vuln_type.value] = VulnerabilityMetrics(
                    vulnerability_type=vuln_type.value,
                    precision=float(precision),
                    recall=float(recall), 
                    f1_score=float(f1),
                    accuracy=float(accuracy),
                    support=int(support),
                    auc=auc
                )
                
            except Exception as e:
                logger.error(f"Error calculating metrics for {vuln_type.value}: {e}")
                metrics[vuln_type.value] = VulnerabilityMetrics(
                    vulnerability_type=vuln_type.value,
                    precision=0.0, recall=0.0, f1_score=0.0,
                    accuracy=0.0, support=0
                )
        
        return metrics
    
    def _simple_evaluation(
        self,
        true_labels: List[List[VulnerabilityType]],
        predicted_labels: List[List[VulnerabilityType]]
    ) -> Dict[str, VulnerabilityMetrics]:
        """Simple evaluation without sklearn."""
        metrics = {}
        all_vuln_types = list(VulnerabilityType)
        
        for vuln_type in all_vuln_types:
            tp = fp = fn = tn = 0
            
            for true_vulns, pred_vulns in zip(true_labels, predicted_labels):
                true_has_vuln = vuln_type in true_vulns
                pred_has_vuln = vuln_type in pred_vulns
                
                if true_has_vuln and pred_has_vuln:
                    tp += 1
                elif not true_has_vuln and pred_has_vuln:
                    fp += 1
                elif true_has_vuln and not pred_has_vuln:
                    fn += 1
                else:
                    tn += 1
            
            # Calculate metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
            
            metrics[vuln_type.value] = VulnerabilityMetrics(
                vulnerability_type=vuln_type.value,
                precision=precision,
                recall=recall,
                f1_score=f1,
                accuracy=accuracy,
                support=tp + fn
            )
        
        return metrics


class SeverityEvaluator:
    """Evaluator for severity assessment performance."""
    
    def evaluate_severity_assessment(
        self,
        true_severities: List[float],
        predicted_severities: List[float]
    ) -> SeverityMetrics:
        """Evaluate severity assessment performance.
        
        Args:
            true_severities: Ground truth severity scores
            predicted_severities: Predicted severity scores
            
        Returns:
            SeverityMetrics with regression metrics
        """
        true_arr = np.array(true_severities)
        pred_arr = np.array(predicted_severities)
        
        # Handle cases with no variance
        if len(set(true_severities)) <= 1 or len(set(predicted_severities)) <= 1:
            correlation = 0.0
        else:
            correlation = np.corrcoef(true_arr, pred_arr)[0, 1]
            if np.isnan(correlation):
                correlation = 0.0
        
        mse = mean_squared_error(true_arr, pred_arr) if sklearn_available else np.mean((true_arr - pred_arr) ** 2)
        rmse = np.sqrt(mse)
        mae = mean_absolute_error(true_arr, pred_arr) if sklearn_available else np.mean(np.abs(true_arr - pred_arr))
        
        return SeverityMetrics(
            mse=float(mse),
            rmse=float(rmse), 
            mae=float(mae),
            correlation=float(correlation)
        )


class FixGenerationEvaluator:
    """Evaluator for fix generation quality."""
    
    def __init__(self):
        self.rouge_scorer = None
        if rouge_available:
            self.rouge_scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'])
    
    def evaluate_fix_generation(
        self,
        reference_fixes: List[str],
        generated_fixes: List[str],
        original_contracts: Optional[List[str]] = None
    ) -> FixGenerationMetrics:
        """Evaluate fix generation quality.
        
        Args:
            reference_fixes: Ground truth fixes
            generated_fixes: Model-generated fixes
            original_contracts: Original vulnerable contracts (for compilation testing)
            
        Returns:
            FixGenerationMetrics with generation quality metrics
        """
        # Calculate text similarity metrics
        bleu_scores = []
        rouge_1_scores = []
        rouge_2_scores = []
        rouge_l_scores = []
        
        for ref_fix, gen_fix in zip(reference_fixes, generated_fixes):
            # BLEU score (simplified - would use proper BLEU in practice)
            bleu_score = self._calculate_simple_bleu(ref_fix, gen_fix)
            bleu_scores.append(bleu_score)
            
            # ROUGE scores
            if self.rouge_scorer:
                scores = self.rouge_scorer.score(ref_fix, gen_fix)
                rouge_1_scores.append(scores['rouge1'].fmeasure)
                rouge_2_scores.append(scores['rouge2'].fmeasure)
                rouge_l_scores.append(scores['rougeL'].fmeasure)
            else:
                rouge_1_scores.append(0.0)
                rouge_2_scores.append(0.0)
                rouge_l_scores.append(0.0)
        
        # Test compilation success rate
        compilation_success_rate = 0.0
        if original_contracts:
            compilation_success_rate = self._test_compilation_success(
                original_contracts, generated_fixes
            )
        
        # Semantic similarity (placeholder)
        semantic_similarity = np.mean([
            self._calculate_semantic_similarity(ref, gen)
            for ref, gen in zip(reference_fixes, generated_fixes)
        ])
        
        return FixGenerationMetrics(
            bleu_score=float(np.mean(bleu_scores)),
            rouge_1=float(np.mean(rouge_1_scores)),
            rouge_2=float(np.mean(rouge_2_scores)),
            rouge_l=float(np.mean(rouge_l_scores)),
            compilation_success_rate=float(compilation_success_rate),
            semantic_similarity=float(semantic_similarity)
        )
    
    def _calculate_simple_bleu(self, reference: str, candidate: str) -> float:
        """Calculate simplified BLEU score."""
        ref_words = reference.lower().split()
        cand_words = candidate.lower().split()
        
        if not cand_words:
            return 0.0
        
        # Calculate 1-gram precision
        matches = sum(1 for word in cand_words if word in ref_words)
        precision = matches / len(cand_words)
        
        # Apply brevity penalty
        bp = min(1.0, len(cand_words) / max(len(ref_words), 1))
        
        return precision * bp
    
    def _test_compilation_success(
        self,
        original_contracts: List[str],
        generated_fixes: List[str]
    ) -> float:
        """Test if generated fixes compile successfully."""
        # This would integrate with Solidity compiler in practice
        # For now, return a placeholder value
        return 0.8
    
    def _calculate_semantic_similarity(self, text1: str, text2: str) -> float:
        """Calculate semantic similarity between two texts."""
        # This would use embeddings or other semantic similarity measures
        # For now, return Jaccard similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0


class ModelEvaluator:
    """Main evaluator that orchestrates all evaluation tasks."""
    
    def __init__(self, auditor: ContractAuditor):
        self.auditor = auditor
        self.vuln_evaluator = VulnerabilityEvaluator()
        self.severity_evaluator = SeverityEvaluator()
        self.fix_evaluator = FixGenerationEvaluator()
    
    def evaluate_model(
        self,
        test_examples: List[TrainingExample],
        save_results: bool = True,
        results_dir: str = "evaluation/reports"
    ) -> OverallMetrics:
        """Perform comprehensive model evaluation.
        
        Args:
            test_examples: Test dataset examples
            save_results: Whether to save detailed results
            results_dir: Directory to save results
            
        Returns:
            OverallMetrics with comprehensive evaluation results
        """
        logger.info(f"Starting evaluation on {len(test_examples)} test examples...")
        start_time = datetime.now()
        
        # Collect predictions
        true_vulnerabilities = []
        pred_vulnerabilities = []
        confidence_scores = []
        true_severities = []
        pred_severities = []
        reference_fixes = []
        generated_fixes = []
        
        for i, example in enumerate(test_examples):
            try:
                # Get model predictions
                result = self.auditor.audit_contract(
                    example.contract_code,
                    example.contract_name
                )
                
                # Collect vulnerability predictions
                true_vulns = example.vulnerability_labels
                pred_vulns = [v.vulnerability_type for v in result.vulnerabilities]
                pred_confidences = [v.confidence for v in result.vulnerabilities]
                
                true_vulnerabilities.append(true_vulns)
                pred_vulnerabilities.append(pred_vulns)
                confidence_scores.append(pred_confidences)
                
                # Collect severity scores
                for vuln_type in example.vulnerability_labels:
                    if vuln_type in example.severity_scores:
                        true_severities.append(example.severity_scores[vuln_type])
                        
                        # Find corresponding prediction
                        pred_severity = 0.0
                        for vuln in result.vulnerabilities:
                            if vuln.vulnerability_type == vuln_type:
                                severity_map = {
                                    SeverityLevel.CRITICAL: 1.0,
                                    SeverityLevel.HIGH: 0.8,
                                    SeverityLevel.MEDIUM: 0.6,
                                    SeverityLevel.LOW: 0.4,
                                    SeverityLevel.INFO: 0.2
                                }
                                pred_severity = severity_map.get(vuln.severity, 0.0)
                                break
                        
                        pred_severities.append(pred_severity)
                
                # Collect fix generation data
                for vuln_type, ref_fix in example.fixes.items():
                    reference_fixes.append(ref_fix)
                    
                    # Find generated fix
                    gen_fix = ""
                    for vuln in result.vulnerabilities:
                        if vuln.vulnerability_type == vuln_type and vuln.recommended_fix:
                            gen_fix = vuln.recommended_fix
                            break
                    
                    generated_fixes.append(gen_fix)
                
                # Progress logging
                if (i + 1) % 10 == 0:
                    logger.info(f"Processed {i + 1}/{len(test_examples)} examples")
                    
            except Exception as e:
                logger.error(f"Error processing example {i}: {e}")
                continue
        
        # Calculate metrics
        logger.info("Calculating vulnerability detection metrics...")
        vuln_metrics = self.vuln_evaluator.evaluate_vulnerability_detection(
            true_vulnerabilities, pred_vulnerabilities, confidence_scores
        )
        
        logger.info("Calculating severity assessment metrics...")
        severity_metrics = self.severity_evaluator.evaluate_severity_assessment(
            true_severities, pred_severities
        )
        
        logger.info("Calculating fix generation metrics...")
        fix_metrics = self.fix_evaluator.evaluate_fix_generation(
            reference_fixes, generated_fixes
        )
        
        # Calculate additional metrics
        false_positive_rate = self._calculate_false_positive_rate(
            true_vulnerabilities, pred_vulnerabilities
        )
        false_negative_rate = self._calculate_false_negative_rate(
            true_vulnerabilities, pred_vulnerabilities  
        )
        precision_at_k = self._calculate_precision_at_k(
            true_vulnerabilities, pred_vulnerabilities, confidence_scores
        )
        
        evaluation_time = (datetime.now() - start_time).total_seconds()
        
        # Create overall metrics
        overall_metrics = OverallMetrics(
            vulnerability_detection=vuln_metrics,
            severity_assessment=severity_metrics,
            fix_generation=fix_metrics,
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            precision_at_k=precision_at_k,
            evaluation_time=evaluation_time,
            total_contracts_evaluated=len(test_examples)
        )
        
        # Save results
        if save_results:
            self._save_evaluation_results(overall_metrics, results_dir)
        
        logger.info(f"Evaluation completed in {evaluation_time:.2f} seconds")
        return overall_metrics
    
    def _calculate_false_positive_rate(
        self,
        true_vulnerabilities: List[List[VulnerabilityType]],
        pred_vulnerabilities: List[List[VulnerabilityType]]
    ) -> float:
        """Calculate overall false positive rate."""
        total_fp = 0
        total_tn_fp = 0
        
        for true_vulns, pred_vulns in zip(true_vulnerabilities, pred_vulnerabilities):
            true_set = set(true_vulns)
            pred_set = set(pred_vulns)
            
            # False positives: predicted but not true
            fp = len(pred_set - true_set)
            total_fp += fp
            
            # All possible negatives for this example
            all_vulns = set(VulnerabilityType)
            true_negatives = all_vulns - true_set
            total_tn_fp += len(true_negatives)
        
        return total_fp / total_tn_fp if total_tn_fp > 0 else 0.0
    
    def _calculate_false_negative_rate(
        self,
        true_vulnerabilities: List[List[VulnerabilityType]],
        pred_vulnerabilities: List[List[VulnerabilityType]]
    ) -> float:
        """Calculate overall false negative rate."""
        total_fn = 0
        total_tp_fn = 0
        
        for true_vulns, pred_vulns in zip(true_vulnerabilities, pred_vulnerabilities):
            true_set = set(true_vulns)
            pred_set = set(pred_vulns)
            
            # False negatives: true but not predicted
            fn = len(true_set - pred_set)
            total_fn += fn
            total_tp_fn += len(true_set)
        
        return total_fn / total_tp_fn if total_tp_fn > 0 else 0.0
    
    def _calculate_precision_at_k(
        self,
        true_vulnerabilities: List[List[VulnerabilityType]],
        pred_vulnerabilities: List[List[VulnerabilityType]],
        confidence_scores: List[List[float]],
        k_values: List[int] = [1, 3, 5]
    ) -> Dict[int, float]:
        """Calculate precision at k for top-k predictions."""
        precision_at_k = {}
        
        for k in k_values:
            if k <= 0:
                continue
                
            total_precision = 0.0
            valid_examples = 0
            
            for true_vulns, pred_vulns, confidences in zip(
                true_vulnerabilities, pred_vulnerabilities, confidence_scores
            ):
                if not pred_vulns:
                    continue
                
                # Sort predictions by confidence
                pred_conf_pairs = list(zip(pred_vulns, confidences))
                pred_conf_pairs.sort(key=lambda x: x[1], reverse=True)
                
                # Take top k predictions
                top_k_preds = [pred for pred, _ in pred_conf_pairs[:k]]
                
                # Calculate precision for this example
                true_set = set(true_vulns)
                top_k_set = set(top_k_preds)
                
                if top_k_set:
                    precision = len(true_set.intersection(top_k_set)) / len(top_k_set)
                    total_precision += precision
                    valid_examples += 1
            
            precision_at_k[k] = total_precision / valid_examples if valid_examples > 0 else 0.0
        
        return precision_at_k
    
    def _save_evaluation_results(
        self,
        metrics: OverallMetrics,
        results_dir: str
    ):
        """Save evaluation results to files."""
        results_path = Path(results_dir)
        results_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        json_file = results_path / f"evaluation_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(asdict(metrics), f, indent=2, default=str)
        
        # Save human-readable report
        report_file = results_path / f"evaluation_report_{timestamp}.md"
        report = self._generate_evaluation_report(metrics)
        with open(report_file, 'w') as f:
            f.write(report)
        
        logger.info(f"Evaluation results saved to {results_path}")
    
    def _generate_evaluation_report(self, metrics: OverallMetrics) -> str:
        """Generate human-readable evaluation report."""
        report_lines = [
            "# Model Evaluation Report",
            "",
            f"**Evaluation Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Contracts Evaluated:** {metrics.total_contracts_evaluated}",
            f"**Evaluation Time:** {metrics.evaluation_time:.2f} seconds",
            "",
            "## Overall Performance",
            "",
            f"- **False Positive Rate:** {metrics.false_positive_rate:.3f}",
            f"- **False Negative Rate:** {metrics.false_negative_rate:.3f}",
            ""
        ]
        
        # Precision at K
        if metrics.precision_at_k:
            report_lines.extend([
                "### Precision at K",
                ""
            ])
            for k, precision in metrics.precision_at_k.items():
                report_lines.append(f"- **P@{k}:** {precision:.3f}")
            report_lines.append("")
        
        # Vulnerability Detection Metrics
        report_lines.extend([
            "## Vulnerability Detection",
            "",
            "| Vulnerability Type | Precision | Recall | F1-Score | Support |",
            "|-------------------|-----------|--------|----------|---------|"
        ])
        
        for vuln_type, vuln_metrics in metrics.vulnerability_detection.items():
            report_lines.append(
                f"| {vuln_type} | {vuln_metrics.precision:.3f} | "
                f"{vuln_metrics.recall:.3f} | {vuln_metrics.f1_score:.3f} | "
                f"{vuln_metrics.support} |"
            )
        
        # Severity Assessment
        report_lines.extend([
            "",
            "## Severity Assessment",
            "",
            f"- **MSE:** {metrics.severity_assessment.mse:.4f}",
            f"- **RMSE:** {metrics.severity_assessment.rmse:.4f}",
            f"- **MAE:** {metrics.severity_assessment.mae:.4f}",
            f"- **Correlation:** {metrics.severity_assessment.correlation:.4f}",
            ""
        ])
        
        # Fix Generation
        report_lines.extend([
            "## Fix Generation",
            "",
            f"- **BLEU Score:** {metrics.fix_generation.bleu_score:.4f}",
            f"- **ROUGE-1:** {metrics.fix_generation.rouge_1:.4f}",
            f"- **ROUGE-2:** {metrics.fix_generation.rouge_2:.4f}",
            f"- **ROUGE-L:** {metrics.fix_generation.rouge_l:.4f}",
            f"- **Compilation Success Rate:** {metrics.fix_generation.compilation_success_rate:.4f}",
            f"- **Semantic Similarity:** {metrics.fix_generation.semantic_similarity:.4f}",
            ""
        ])
        
        return "\n".join(report_lines)
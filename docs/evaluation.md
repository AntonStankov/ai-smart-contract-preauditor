# Evaluation Metrics

This document describes the comprehensive evaluation framework used to assess Contract AI Auditor model performance.

## Overview

The evaluation framework measures model performance across multiple dimensions:
- **Vulnerability Detection:** Classification accuracy and coverage
- **Severity Assessment:** Regression accuracy for risk levels  
- **Fix Generation:** Quality and effectiveness of suggested fixes
- **False Positive/Negative Analysis:** Error characterization
- **Computational Efficiency:** Speed and resource usage

## Vulnerability Detection Metrics

### Classification Metrics

For each vulnerability type, we compute standard classification metrics:

#### Precision
```
Precision = True Positives / (True Positives + False Positives)
```
- Measures accuracy of positive predictions
- High precision = few false alarms
- Target: >0.8 for critical vulnerabilities

#### Recall  
```
Recall = True Positives / (True Positives + False Negatives)
```
- Measures coverage of actual vulnerabilities
- High recall = few missed vulnerabilities
- Target: >0.9 for critical vulnerabilities

#### F1-Score
```
F1 = 2 * (Precision * Recall) / (Precision + Recall)
```
- Harmonic mean of precision and recall
- Balances both metrics
- Primary optimization target

#### Support
- Number of true instances for each vulnerability type
- Indicates reliability of metrics
- Minimum 10 instances for reliable metrics

### Multi-Label Classification

Since contracts can have multiple vulnerabilities:

#### Hamming Loss
```
Hamming Loss = (1/N) * Σ(XOR(y_true, y_pred)) / num_labels
```
- Average fraction of incorrect labels
- Lower is better
- Range: [0, 1]

#### Subset Accuracy
```
Subset Accuracy = (1/N) * Σ(y_true == y_pred)
```
- Fraction of samples with exactly correct label set
- Strict metric - all labels must match
- Range: [0, 1]

#### Jaccard Index
```
Jaccard = |y_true ∩ y_pred| / |y_true ∪ y_pred|
```
- Overlap between true and predicted label sets
- Robust to label imbalance
- Range: [0, 1]

### Confidence Calibration

Assesses how well confidence scores reflect actual accuracy:

#### Expected Calibration Error (ECE)
```
ECE = Σ(m_i/n) * |accuracy_i - confidence_i|
```
- Measures gap between confidence and accuracy
- Computed over confidence bins
- Target: <0.1

#### Reliability Diagram
- Plots accuracy vs confidence bins
- Perfect calibration = diagonal line
- Visual assessment of over/under-confidence

### ROC and Precision-Recall Curves

#### AUC-ROC
- Area under Receiver Operating Characteristic curve
- Measures discriminative ability across all thresholds
- Range: [0, 1], higher is better

#### AUC-PR  
- Area under Precision-Recall curve
- More informative for imbalanced datasets
- Range: [0, 1], higher is better

## Severity Assessment Metrics

### Regression Metrics

Severity scores are continuous values [0, 1]:

#### Mean Squared Error (MSE)
```
MSE = (1/n) * Σ(y_true - y_pred)²
```
- Penalizes large errors heavily
- Target: <0.1 for severity assessment

#### Root Mean Squared Error (RMSE)
```
RMSE = √MSE
```
- Same units as target variable
- Interpretable error magnitude

#### Mean Absolute Error (MAE)
```
MAE = (1/n) * Σ|y_true - y_pred|
```
- Average absolute deviation
- Robust to outliers
- Target: <0.15

#### R² Score
```
R² = 1 - (SS_res / SS_tot)
```
- Coefficient of determination
- Proportion of variance explained
- Target: >0.7

### Correlation Analysis

#### Pearson Correlation
```
r = Σ(x_i - x̄)(y_i - ȳ) / √[Σ(x_i - x̄)²Σ(y_i - ȳ)²]
```
- Linear relationship strength
- Range: [-1, 1]
- Target: >0.8

#### Spearman Correlation
- Rank-based correlation
- Captures monotonic relationships
- Robust to non-linear patterns

### Ordinal Classification

When treating severity as ordinal categories:

#### Kendall's Tau
- Rank correlation coefficient
- Measures ordinal association
- Range: [-1, 1]

#### Weighted Kappa
- Inter-rater agreement for ordinal data
- Accounts for disagreement severity
- Range: [-1, 1]

## Fix Generation Metrics

### Text Similarity Metrics

#### BLEU Score
```
BLEU = BP * exp(Σ w_n * log(p_n))
```
- Measures n-gram precision with brevity penalty
- Standard for text generation evaluation
- Range: [0, 1], higher is better

#### ROUGE Scores

**ROUGE-1:** Unigram overlap
```
ROUGE-1 = |unigrams_ref ∩ unigrams_hyp| / |unigrams_ref|
```

**ROUGE-2:** Bigram overlap  
**ROUGE-L:** Longest common subsequence

#### BERTScore
- Semantic similarity using contextual embeddings
- More robust than n-gram metrics
- Range: [0, 1]

### Code-Specific Metrics

#### Abstract Syntax Tree (AST) Similarity
- Compares code structure
- Language-aware comparison
- Ignores formatting differences

#### Edit Distance
```
Edit Distance = min operations to transform reference to hypothesis
```
- Levenshtein distance between code strings
- Normalized by reference length

#### Compilation Success Rate
```
Compilation Rate = (# compilable fixes) / (# total fixes)
```
- Fraction of generated fixes that compile
- Basic correctness check
- Target: >0.8

### Functional Correctness

#### Test Case Pass Rate
```
Pass Rate = (# tests passed by fix) / (# total tests)
```
- Measures fix effectiveness
- Requires comprehensive test suite
- Target: >0.9

#### Vulnerability Resolution Rate  
```
Resolution Rate = (# vulnerabilities fixed) / (# vulnerabilities detected)
```
- Whether fix actually resolves the vulnerability
- Verified through static analysis
- Target: >0.85

#### Gas Impact Analysis
- Change in gas costs after applying fix
- Efficiency vs security trade-off
- Measured as percentage change

## Overall Model Performance

### Aggregate Metrics

#### Macro-Averaged F1
```
Macro F1 = (1/C) * Σ F1_c
```
- Average F1 across all vulnerability classes
- Treats all classes equally
- Good for balanced evaluation

#### Micro-Averaged F1
```
Micro F1 = 2 * (Σ TP) / (2 * Σ TP + Σ FP + Σ FN)
```
- Global F1 across all instances
- Dominated by frequent classes
- Reflects overall accuracy

#### Weighted F1
```
Weighted F1 = Σ (support_c / total) * F1_c
```
- F1 weighted by class frequency
- Balances macro and micro approaches

### Risk-Adjusted Metrics

#### Critical Vulnerability Recall
- Recall specifically for critical vulnerabilities
- Most important for security applications
- Target: >0.95

#### Severity-Weighted F1
```
SW-F1 = Σ severity_weight_c * F1_c / Σ severity_weight_c
```
- F1 weighted by vulnerability severity
- Emphasizes important vulnerabilities

### False Positive Analysis

#### False Positive Rate
```
FPR = FP / (FP + TN)
```
- Fraction of safe code flagged as vulnerable
- Important for usability
- Target: <0.1

#### Precision at K
```
P@K = (# relevant in top K) / K
```
- Precision in top K predictions
- Useful for ranking evaluation
- Computed for K = 1, 3, 5

#### False Discovery Rate
```
FDR = FP / (FP + TP) = 1 - Precision
```
- Fraction of detections that are false
- Directly impacts user trust

### False Negative Analysis

#### False Negative Rate
```
FNR = FN / (FN + TP) = 1 - Recall
```
- Fraction of vulnerabilities missed
- Critical for security applications
- Target: <0.05 for critical vulnerabilities

#### Miss Rate by Severity
- FNR broken down by severity level
- Ensures critical issues aren't missed
- Different targets per severity

## Computational Metrics

### Inference Speed

#### Throughput
```
Throughput = contracts processed / time
```
- Contracts audited per second
- Hardware-dependent metric
- Target: >1 contract/second on GPU

#### Latency
```
Latency = time per contract
```
- Time to audit single contract
- Important for interactive use
- Target: <10 seconds per contract

### Resource Usage

#### GPU Memory
- Peak GPU memory during inference
- Determines maximum batch size
- Measured in GB

#### CPU Utilization
- Processor usage during inference
- Affects system responsiveness
- Measured as percentage

#### Energy Consumption
- Power usage for sustainability analysis
- Measured in kWh per audit
- Increasingly important metric

## Evaluation Datasets

### Test Set Composition

#### Held-out Test Set
- 15% of total data
- Never used during training
- Stratified by vulnerability type and severity

#### Challenge Set
- Curated difficult examples
- Edge cases and rare vulnerabilities
- Tests model robustness

#### Temporal Test Set
- Recent contracts not in training
- Tests generalization to new patterns
- Updated quarterly

### Cross-Validation

#### K-Fold Cross-Validation
- K=5 folds for robust evaluation
- Ensures results aren't dataset-specific
- Reports mean and standard deviation

#### Time-Series Split
- Chronological train/test splits
- Simulates deployment scenario
- Tests temporal generalization

## Baseline Comparisons

### Rule-Based Systems
- Slither static analyzer
- MythX commercial tool
- Oyente academic tool

### Commercial Tools
- ConsenSys Diligence
- CertiK static analysis
- Quantstamp protocol

### Academic Models
- Recent research publications
- Open-source implementations
- Fair comparison protocols

## Statistical Significance

### Hypothesis Testing

#### McNemar's Test
- Tests significance of classification differences
- Paired test for same test set
- p-value < 0.05 for significance

#### Paired t-Test
- Tests significance of regression metric differences
- Assumes normal distribution of differences
- Reports confidence intervals

#### Bootstrap Resampling
- Non-parametric significance testing
- 1000+ bootstrap samples
- Robust to distribution assumptions

### Effect Size

#### Cohen's d
```
d = (mean1 - mean2) / pooled_standard_deviation
```
- Standardized effect size
- 0.2 small, 0.5 medium, 0.8 large effect

#### Glass's Δ
- Effect size using control group SD
- Appropriate when SDs differ significantly

## Reporting Standards

### Metric Reporting

Required metrics for each evaluation:
1. **Per-class metrics:** Precision, Recall, F1, Support
2. **Aggregate metrics:** Macro F1, Micro F1, Weighted F1
3. **Error analysis:** FPR, FNR, Confusion matrix
4. **Confidence intervals:** 95% CI for all metrics
5. **Statistical significance:** p-values vs baselines

### Visualization

#### Confusion Matrix
- Visual representation of classification errors
- Normalized and absolute counts
- Per-class error patterns

#### ROC Curves
- One curve per vulnerability type
- Includes AUC values
- Confidence intervals shown

#### Calibration Plots
- Reliability diagrams
- Perfect calibration reference
- ECE values displayed

### Reproducibility

#### Random Seeds
- Fixed seeds for all random operations
- Enables exact reproduction
- Reported in methodology

#### Hardware Specifications
- GPU/CPU models and memory
- Software versions (CUDA, PyTorch)
- Docker containers for consistency

#### Data Splits
- Exact train/val/test indices
- Stratification methodology
- Version control for datasets

## Interpretation Guidelines

### Metric Thresholds

| Metric | Excellent | Good | Acceptable | Poor |
|--------|-----------|------|------------|------|
| Precision | >0.9 | >0.8 | >0.7 | <0.7 |
| Recall | >0.9 | >0.8 | >0.7 | <0.7 |  
| F1-Score | >0.9 | >0.8 | >0.7 | <0.7 |
| RMSE (severity) | <0.1 | <0.15 | <0.2 | >0.2 |
| FPR | <0.05 | <0.1 | <0.15 | >0.15 |

### Context Considerations

#### Deployment Environment
- Interactive vs batch processing
- Latency vs throughput requirements
- Resource constraints

#### User Expertise
- Security expert vs developer
- Tolerance for false positives
- Need for explanations

#### Risk Profile
- Financial value at stake
- Regulatory requirements
- Update frequency

This evaluation framework ensures comprehensive assessment of model capabilities while providing actionable insights for improvement and deployment decisions.
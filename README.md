# Contract AI Auditor

An open-source AI model for smart contract security auditing that detects vulnerabilities, classifies severity, explains root causes, and proposes secure fixes.

## 🎯 Features

- **Vulnerability Detection**: Multi-label classification of smart contract vulnerabilities
- **Severity Assessment**: Automated severity scoring based on impact and exploitability
- **Root Cause Analysis**: Natural language explanations of vulnerability patterns
- **Fix Generation**: Automatic generation of secure code patches
- **Testing Integration**: Foundry/Hardhat test generation and validation
- **Offline Capable**: No external API dependencies, fully self-contained

## 🏗️ Architecture

### Base Models Supported
- CodeLLaMA
- StarCoder2  
- DeepSeek-Coder
- Phi-3

### Training Tasks
- Multi-label vulnerability classification
- Sequence-to-sequence fix generation
- Natural language explanation generation

## 📊 Dataset Sources

- **SWC Registry**: Smart contract weakness classification
- **OpenZeppelin Audits**: Professional audit reports and fixes
- **Immunefi**: Bug bounty disclosures and patches
- **Ethernaut**: Educational vulnerable contracts
- **Damn Vulnerable DeFi**: DeFi-specific vulnerabilities
- **Slither**: Static analysis test corpus

## 🚀 Quick Start

### Installation

```bash
git clone <repository-url>
cd contract-ai-auditor
pip install -r requirements.txt
```

### Data Preparation

```bash
python data/collect_data.py --sources all
python data/process_data.py --output data/processed/
```

### Training

```bash
python training/train.py --config training/configs/codellama_base.yaml
```

### Inference

```bash
python auditor/audit.py --contract contracts/examples/sample.sol
```

## 📁 Project Structure

```
contract-ai-auditor/
├── data/                   # Dataset management
│   ├── raw/               # Raw collected data
│   ├── processed/         # Processed training data
│   └── splits/            # Train/val/test splits
├── training/              # Model training pipeline
│   ├── configs/           # Training configurations
│   ├── scripts/           # Training scripts
│   └── models/            # Saved model checkpoints
├── evaluation/            # Model evaluation
│   ├── metrics/           # Evaluation metrics
│   └── reports/           # Evaluation reports
├── inference/             # Inference pipeline
├── auditor/               # Main auditing interface
├── contracts/             # Smart contract examples
│   ├── examples/          # Sample contracts
│   ├── vulnerable/        # Known vulnerable contracts
│   └── patched/           # Patched versions
├── tests/                 # Test suites
│   ├── unit/              # Unit tests
│   └── integration/       # Integration tests
└── docs/                  # Documentation
```

## 🔒 Security

This project is designed for security research and education. Key security principles:

- **Local Only**: No external API calls during inference
- **Sandboxed Testing**: All contract testing on local blockchain only
- **Secure Defaults**: Conservative vulnerability classification
- **Reproducible**: Deterministic training and inference

## 📖 Documentation

- [Training Guide](docs/training.md)
- [Dataset Schema](docs/dataset_schema.md)
- [API Reference](docs/api.md)
- [Evaluation Metrics](docs/evaluation.md)

## 🤝 Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is for educational and research purposes. Always conduct professional security audits for production smart contracts.
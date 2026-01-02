#!/bin/bash

# Contract AI Auditor Setup Script

set -e

echo "🚀 Setting up Contract AI Auditor development environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.9"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.9+ required. Found: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment
echo "🔧 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install core dependencies
echo "📦 Installing core dependencies..."
pip install -r requirements.txt

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install -r requirements-dev.txt

# Install pre-commit hooks
echo "🔒 Setting up pre-commit hooks..."
pre-commit install

# Create necessary directories
echo "📁 Creating additional directories..."
mkdir -p logs
mkdir -p experiments
mkdir -p checkpoints

# Install Foundry (optional - for blockchain testing)
echo "🔨 Installing Foundry (optional)..."
if ! command -v forge &> /dev/null; then
    echo "ℹ️  Foundry not found. Installing Foundry for blockchain testing..."
    if curl -L https://foundry.paradigm.xyz | bash; then
        # Add Foundry to PATH for this session
        export PATH="$HOME/.foundry/bin:$PATH"
        if command -v foundryup &> /dev/null; then
            foundryup
            echo "✅ Foundry installed successfully"
        else
            echo "⚠️  Foundry installation may need manual PATH setup"
            echo "   Run: export PATH=\"\$HOME/.foundry/bin:\$PATH\""
        fi
    else
        echo "⚠️  Foundry installation failed - blockchain testing will be limited"
        echo "   You can install it later with: curl -L https://foundry.paradigm.xyz | bash"
    fi
else
    echo "✅ Foundry already installed"
fi

# Verify installations
echo "🔍 Verifying installations..."
python -c "import torch; print(f'PyTorch: {torch.__version__}')"
python -c "import transformers; print(f'Transformers: {transformers.__version__}')"
python -c "import web3; print(f'Web3: {web3.__version__}')"

echo "✅ Setup complete!"
echo ""
echo "🎯 Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run data collection: python data/collect_data.py"
echo "3. Start training: python training/train.py"
echo ""
echo "📖 See README.md for detailed usage instructions"
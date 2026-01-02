#!/usr/bin/env python3
"""
Contract AI Auditor
A machine learning-based smart contract security auditing system.
"""

__version__ = "0.1.0"
__author__ = "Contract AI Auditor Team"
__description__ = "AI-powered smart contract security auditing"

from auditor.core import ContractAuditor
from auditor.models import VulnerabilityClassifier, FixGenerator
from auditor.utils import load_model, preprocess_contract

__all__ = [
    "ContractAuditor",
    "VulnerabilityClassifier", 
    "FixGenerator",
    "load_model",
    "preprocess_contract"
]
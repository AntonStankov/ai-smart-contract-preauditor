"""
Data collection utilities for smart contract vulnerability datasets.
"""

from typing import Dict, List, Optional
import json
import os
from pathlib import Path
import logging

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False
    print("Warning: 'requests' library not available. Web-based data collection will be limited.")

try:
    from web3 import Web3
    HAS_WEB3 = True
except ImportError:
    Web3 = None
    HAS_WEB3 = False
    print("Warning: 'web3' library not available. Blockchain data collection will be limited.")

from .schema import (
    ContractAuditData, ContractSource, Vulnerability, VulnerabilityLocation,
    VulnerabilityType, SeverityLevel, VulnerabilityImpact
)

logger = logging.getLogger(__name__)


class SWCCollector:
    """Collector for SWC (Smart Contract Weakness Classification) registry data."""
    
    def __init__(self, cache_dir: str = "data/cache/swc"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.base_url = "https://swcregistry.io"
    
    def collect_all(self) -> List[ContractAuditData]:
        """Collect all SWC examples."""
        if not HAS_REQUESTS:
            logger.warning("Requests library not available. Using local examples only.")
            
        audit_data = []
        
        # Define SWC IDs and their mappings
        swc_mappings = {
            "SWC-107": VulnerabilityType.REENTRANCY,
            "SWC-101": VulnerabilityType.INTEGER_OVERFLOW,
            "SWC-104": VulnerabilityType.UNCHECKED_CALL,
            "SWC-105": VulnerabilityType.ACCESS_CONTROL,
            "SWC-128": VulnerabilityType.DOS_GAS_LIMIT,
            "SWC-116": VulnerabilityType.TIMESTAMP_DEPENDENCE,
            "SWC-115": VulnerabilityType.TX_ORIGIN,
            "SWC-112": VulnerabilityType.DELEGATECALL,
            "SWC-109": VulnerabilityType.UNINITIALIZED_STORAGE,
            "SWC-103": VulnerabilityType.FLOATING_PRAGMA,
        }
        
        for swc_id, vuln_type in swc_mappings.items():
            try:
                examples = self._collect_swc_examples(swc_id, vuln_type)
                audit_data.extend(examples)
                logger.info(f"Collected {len(examples)} examples for {swc_id}")
            except Exception as e:
                logger.error(f"Failed to collect {swc_id}: {e}")
        
        return audit_data
    
    def _collect_swc_examples(self, swc_id: str, vuln_type: VulnerabilityType) -> List[ContractAuditData]:
        """Collect examples for a specific SWC ID."""
        # This is a placeholder - in reality you'd scrape from SWC registry
        # or use their GitHub repository
        examples = []
        
        # Placeholder example data - replace with actual SWC data collection
        if swc_id == "SWC-107":  # Reentrancy example
            contract_code = '''
pragma solidity ^0.4.19;

contract ReentrancyVictim {
    mapping (address => uint) userBalance;
    
    function withdrawBalance() public {
        uint amountToWithdraw = userBalance[msg.sender];
        if (msg.sender.call.value(amountToWithdraw)()) { // Vulnerable line
            userBalance[msg.sender] = 0;
        }
    }
    
    function deposit() public payable {
        userBalance[msg.sender] += msg.value;
    }
}
'''
            
            fixed_code = '''
pragma solidity ^0.4.19;

contract ReentrancyFixed {
    mapping (address => uint) userBalance;
    
    function withdrawBalance() public {
        uint amountToWithdraw = userBalance[msg.sender];
        userBalance[msg.sender] = 0;  // Update state first
        if (!msg.sender.call.value(amountToWithdraw)()) {
            userBalance[msg.sender] = amountToWithdraw;  // Revert on failure
        }
    }
    
    function deposit() public payable {
        userBalance[msg.sender] += msg.value;
    }
}
'''
            
            vulnerability = Vulnerability(
                vulnerability_type=vuln_type,
                severity=SeverityLevel.CRITICAL,
                impact=[VulnerabilityImpact.FUNDS_LOSS],
                location=VulnerabilityLocation(
                    line_start=7,
                    line_end=7,
                    function_name="withdrawBalance",
                    contract_name="ReentrancyVictim"
                ),
                affected_code="if (msg.sender.call.value(amountToWithdraw)()) {",
                title="Reentrancy Vulnerability",
                description="The contract updates the user balance after the external call, allowing for reentrancy attacks.",
                root_cause="State changes occur after external calls, violating the checks-effects-interactions pattern.",
                exploit_scenario="An attacker can create a malicious contract that recursively calls withdrawBalance() before the balance is set to zero.",
                recommended_fix="Update the user balance before making the external call (checks-effects-interactions pattern).",
                fixed_code=fixed_code,
                confidence=1.0,
                references=["https://swcregistry.io/docs/SWC-107"],
                tags=["reentrancy", "external-call", "state-change"]
            )
            
            audit_data = ContractAuditData(
                contract_source=ContractSource(
                    file_path=f"swc/{swc_id}_example.sol",
                    content=contract_code,
                    compiler_version="0.4.19"
                ),
                contract_name="ReentrancyVictim",
                vulnerabilities=[vulnerability],
                source_dataset="SWC"
            )
            
            examples.append(audit_data)
        
        return examples


class EthernautCollector:
    """Collector for Ethernaut challenge data."""
    
    def __init__(self, cache_dir: str = "data/cache/ethernaut"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_all(self) -> List[ContractAuditData]:
        """Collect all Ethernaut challenges."""
        # Placeholder - implement actual Ethernaut data collection
        return []


class ImmuneFiCollector:
    """Collector for ImmuneFi bug bounty reports."""
    
    def __init__(self, cache_dir: str = "data/cache/immunefi"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_all(self) -> List[ContractAuditData]:
        """Collect ImmuneFi reports."""
        # Placeholder - implement actual ImmuneFi data collection
        return []


class OpenZeppelinCollector:
    """Collector for OpenZeppelin audit reports."""
    
    def __init__(self, cache_dir: str = "data/cache/openzeppelin"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_all(self) -> List[ContractAuditData]:
        """Collect OpenZeppelin audit reports."""
        # Placeholder - implement actual OpenZeppelin data collection
        return []


class SlitherCorpusCollector:
    """Collector for Slither test corpus."""
    
    def __init__(self, cache_dir: str = "data/cache/slither"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_all(self) -> List[ContractAuditData]:
        """Collect Slither test cases."""
        # Placeholder - implement actual Slither corpus collection
        return []


class DamnVulnerableDeFiCollector:
    """Collector for Damn Vulnerable DeFi challenges."""
    
    def __init__(self, cache_dir: str = "data/cache/dvd"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_all(self) -> List[ContractAuditData]:
        """Collect Damn Vulnerable DeFi challenges."""
        # Placeholder - implement actual DVD data collection
        return []


class DataCollector:
    """Main data collector that orchestrates all data sources."""
    
    def __init__(self, output_dir: str = "data/raw"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.collectors = {
            "swc": SWCCollector(),
            "ethernaut": EthernautCollector(),
            "immunefi": ImmuneFiCollector(),
            "openzeppelin": OpenZeppelinCollector(),
            "slither": SlitherCorpusCollector(),
            "dvd": DamnVulnerableDeFiCollector()
        }
    
    def collect_all_sources(self) -> Dict[str, List[ContractAuditData]]:
        """Collect data from all sources."""
        collected_data = {}
        
        for source_name, collector in self.collectors.items():
            try:
                logger.info(f"Collecting data from {source_name}...")
                data = collector.collect_all()
                collected_data[source_name] = data
                logger.info(f"Collected {len(data)} examples from {source_name}")
                
                # Save raw data
                self._save_raw_data(source_name, data)
                
            except Exception as e:
                logger.error(f"Failed to collect from {source_name}: {e}")
                collected_data[source_name] = []
        
        return collected_data
    
    def collect_source(self, source_name: str) -> List[ContractAuditData]:
        """Collect data from a specific source."""
        if source_name not in self.collectors:
            raise ValueError(f"Unknown source: {source_name}")
        
        collector = self.collectors[source_name]
        data = collector.collect_all()
        self._save_raw_data(source_name, data)
        return data
    
    def _save_raw_data(self, source_name: str, data: List[ContractAuditData]):
        """Save raw audit data to disk."""
        output_file = self.output_dir / f"{source_name}_raw.jsonl"
        
        with open(output_file, 'w') as f:
            for audit in data:
                f.write(json.dumps(audit, cls=SchemaEncoder) + '\n')
        
        logger.info(f"Saved {len(data)} examples to {output_file}")


# Import SchemaEncoder from schema module
from .schema import SchemaEncoder
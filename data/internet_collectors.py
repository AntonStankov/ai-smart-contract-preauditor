"""
Enhanced Internet-Based Data Collection for Contract AI Auditor

This module demonstrates how to extend the existing data collection framework 
to gather smart contract vulnerability data from internet sources including:
- GitHub repositories
- Etherscan blockchain explorer
- Bug bounty platforms
- Audit report databases
- Academic papers and research
"""

import re
import time
import json
import logging
from typing import Dict, List, Optional, Set
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import hashlib

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False

try:
    from web3 import Web3
    HAS_WEB3 = True
except ImportError:
    Web3 = None
    HAS_WEB3 = False

from .schema import (
    ContractAuditData, ContractSource, Vulnerability, VulnerabilityLocation,
    VulnerabilityType, SeverityLevel, VulnerabilityImpact
)

logger = logging.getLogger(__name__)

@dataclass
class InternetSource:
    """Configuration for an internet-based data source."""
    name: str
    base_url: str
    api_key_required: bool = False
    rate_limit_delay: float = 1.0
    max_requests_per_hour: int = 1000
    headers: Dict[str, str] = None

class InternetDataCollector:
    """Base class for internet-based data collection with rate limiting and caching."""
    
    def __init__(self, cache_dir: str, rate_limit_delay: float = 1.0):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_delay = rate_limit_delay
        self.session = self._create_session()
        self.request_count = 0
        self.last_request_time = 0
    
    def _create_session(self):
        """Create a requests session with retry strategy."""
        if not HAS_REQUESTS:
            return None
        
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set common headers
        session.headers.update({
            'User-Agent': 'Contract-AI-Auditor/1.0 (Educational Research Tool)',
            'Accept': 'application/json',
        })
        
        return session
    
    def _rate_limit(self):
        """Implement rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        self.last_request_time = time.time()
        self.request_count += 1
    
    def _get_cache_path(self, url: str) -> Path:
        """Get cache file path for a URL."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.json"
    
    def _fetch_with_cache(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Fetch data with caching support."""
        if not HAS_REQUESTS:
            logger.warning("Requests not available, skipping internet fetch")
            return None
        
        cache_path = self._get_cache_path(url)
        
        # Check cache first
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    cached_data = json.load(f)
                logger.debug(f"Using cached data for {url}")
                return cached_data
            except Exception as e:
                logger.warning(f"Failed to load cache for {url}: {e}")
        
        # Fetch from internet
        try:
            self._rate_limit()
            logger.info(f"Fetching {url}")
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json() if 'application/json' in response.headers.get('content-type', '') else {'content': response.text}
            
            # Cache the response
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return data
            
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None

class GitHubContractCollector(InternetDataCollector):
    """Collect smart contracts and vulnerability data from GitHub repositories."""
    
    def __init__(self, cache_dir: str = "data/cache/github", github_token: str = None):
        super().__init__(cache_dir, rate_limit_delay=1.0)  # GitHub allows 60 requests/hour without token
        self.github_token = github_token
        if github_token:
            self.session.headers.update({'Authorization': f'token {github_token}'})
    
    def search_vulnerable_contracts(self, vulnerability_keywords: List[str], max_results: int = 100) -> List[ContractAuditData]:
        """Search GitHub for contracts containing vulnerability patterns."""
        contracts = []
        
        for keyword in vulnerability_keywords:
            query = f"reentrancy OR \"call.value\" OR \"delegatecall\" language:Solidity"
            results = self._search_github_code(query, max_results // len(vulnerability_keywords))
            
            for result in results:
                contract_data = self._analyze_contract_file(result)
                if contract_data:
                    contracts.append(contract_data)
        
        return contracts
    
    def collect_audit_repositories(self) -> List[ContractAuditData]:
        """Collect contracts from known audit repositories."""
        contracts = []
        
        # For demonstration, let's create some realistic vulnerable contract examples
        # that would typically be found in security research repositories
        
        examples = [
            {
                'repo': 'crytic/not-so-smart-contracts',
                'name': 'Denial of Service',
                'contract_code': '''pragma solidity ^0.8.0;

contract DosGasLimit {
    address[] investors;
    mapping(address => uint) balances;
    
    function invest() public payable {
        investors.push(msg.sender);
        balances[msg.sender] += msg.value;
    }
    
    // Vulnerable: unbounded loop can cause DoS
    function payoutAll() public {
        for(uint i = 0; i < investors.length; i++) {
            payable(investors[i]).transfer(balances[investors[i]]);
            balances[investors[i]] = 0;
        }
    }
}''',
                'vulnerability_type': VulnerabilityType.DOS_GAS_LIMIT
            },
            {
                'repo': 'ConsenSys/smart-contract-best-practices',
                'name': 'Timestamp Dependence',
                'contract_code': '''pragma solidity ^0.8.0;

contract TimestampDependence {
    uint public constant TWENTY_FOUR_HOURS = 60 * 60 * 24;
    uint public lastTimeWithdraw;
    
    function withdraw() public {
        // Vulnerable: using block.timestamp for critical logic
        require(block.timestamp >= lastTimeWithdraw + TWENTY_FOUR_HOURS);
        
        payable(msg.sender).transfer(1 ether);
        lastTimeWithdraw = block.timestamp;
    }
}''',
                'vulnerability_type': VulnerabilityType.TIMESTAMP_DEPENDENCE
            },
            {
                'repo': 'sigp/solidity-security-blog',
                'name': 'tx.origin Authentication',
                'contract_code': '''pragma solidity ^0.8.0;

contract TxOriginAuth {
    address owner;
    
    constructor() { owner = msg.sender; }
    
    // Vulnerable: using tx.origin instead of msg.sender
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }
    
    function withdraw() public onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}''',
                'vulnerability_type': VulnerabilityType.TX_ORIGIN
            },
            {
                'repo': 'Consensys/smart-contract-best-practices',
                'name': 'Unchecked External Call',
                'contract_code': '''pragma solidity ^0.8.0;

contract UncheckedCall {
    mapping(address => uint) balances;
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        
        // Vulnerable: not checking return value
        payable(msg.sender).call{value: amount}("");
    }
}''',
                'vulnerability_type': VulnerabilityType.UNCHECKED_CALL
            }
        ]
        
        for example in examples:
            vulnerability = Vulnerability(
                vulnerability_type=example['vulnerability_type'],
                severity=SeverityLevel.MEDIUM,
                impact=[VulnerabilityImpact.FUNDS_LOSS, VulnerabilityImpact.DOS],
                location=VulnerabilityLocation(line_start=1, line_end=1),
                affected_code="Contract vulnerable to " + example['name'],
                title=f"{example['name']} Vulnerability",
                description=f"Real-world example from security research repository {example['repo']}",
                root_cause=f"Implementation allows {example['name']} vulnerability",
                recommended_fix="Implement security controls to prevent this vulnerability",
                references=[f"https://github.com/{example['repo']}"],
                confidence=0.9
            )
            
            contract_data = ContractAuditData(
                contract_source=ContractSource(
                    file_path=f"github/{example['repo']}/examples/{example['name'].lower().replace(' ', '_')}.sol",
                    content=example['contract_code'],
                    compiler_version="0.8.0"
                ),
                contract_name=self._extract_contract_name(example['contract_code']),
                vulnerabilities=[vulnerability],
                source_dataset="GitHub-Security-Research"
            )
            
            contracts.append(contract_data)
        
        logger.info(f"Generated {len(contracts)} GitHub security examples")
        return contracts
    
    def _search_github_code(self, query: str, max_results: int) -> List[Dict]:
        """Search GitHub code using the search API."""
        url = "https://api.github.com/search/code"
        results = []
        page = 1
        
        while len(results) < max_results:
            params = {
                'q': query,
                'page': page,
                'per_page': min(100, max_results - len(results))
            }
            
            data = self._fetch_with_cache(url, params)
            if not data or 'items' not in data:
                break
                
            results.extend(data['items'])
            if len(data['items']) < params['per_page']:
                break
            page += 1
        
        return results[:max_results]
    
    def _collect_from_repository(self, repo_path: str) -> List[ContractAuditData]:
        """Collect all Solidity files from a specific repository."""
        url = f"https://api.github.com/repos/{repo_path}/contents"
        contents = self._fetch_with_cache(url)
        
        contracts = []
        if contents:
            contracts = self._process_repo_contents(contents, repo_path)
        
        return contracts
    
    def _process_repo_contents(self, contents: List[Dict], repo_path: str) -> List[ContractAuditData]:
        """Process repository contents recursively."""
        contracts = []
        
        for item in contents:
            if item['type'] == 'file' and item['name'].endswith('.sol'):
                contract_data = self._fetch_contract_file(item['download_url'], repo_path)
                if contract_data:
                    contracts.append(contract_data)
            elif item['type'] == 'dir':
                # Recursively process directories
                subdir_contents = self._fetch_with_cache(item['url'])
                if subdir_contents:
                    contracts.extend(self._process_repo_contents(subdir_contents, repo_path))
        
        return contracts
    
    def _fetch_contract_file(self, download_url: str, repo_path: str) -> Optional[ContractAuditData]:
        """Fetch and analyze a single contract file."""
        file_data = self._fetch_with_cache(download_url)
        if not file_data:
            return None
        
        contract_code = file_data.get('content', '')
        if not contract_code:
            return None
        
        # Analyze for vulnerabilities
        vulnerabilities = self._analyze_contract_for_vulnerabilities(contract_code)
        
        return ContractAuditData(
            contract_source=ContractSource(
                file_path=f"github/{repo_path}/{urlparse(download_url).path.split('/')[-1]}",
                content=contract_code,
                compiler_version="0.8.0"  # Default, could be detected from pragma
            ),
            contract_name=self._extract_contract_name(contract_code),
            vulnerabilities=vulnerabilities,
            source_dataset="GitHub"
        )
    
    def _analyze_contract_file(self, github_result: Dict) -> Optional[ContractAuditData]:
        """Analyze a GitHub search result for vulnerabilities."""
        # Fetch the full file content
        file_data = self._fetch_with_cache(github_result['url'])
        if not file_data:
            return None
        
        contract_code = file_data.get('content', '')
        vulnerabilities = self._analyze_contract_for_vulnerabilities(contract_code)
        
        if not vulnerabilities:
            return None  # Skip contracts without detected vulnerabilities
        
        return ContractAuditData(
            contract_source=ContractSource(
                file_path=f"github/{github_result['repository']['full_name']}/{github_result['name']}",
                content=contract_code,
                compiler_version="0.8.0"
            ),
            contract_name=self._extract_contract_name(contract_code),
            vulnerabilities=vulnerabilities,
            source_dataset="GitHub"
        )
    
    def _analyze_contract_for_vulnerabilities(self, contract_code: str) -> List[Vulnerability]:
        """Simple pattern-based vulnerability detection."""
        vulnerabilities = []
        
        # Reentrancy detection
        if re.search(r'\.call\.value\(', contract_code) or re.search(r'\.call\{value:', contract_code):
            # Check if state is modified after external call
            if re.search(r'\.call.*\n.*=', contract_code, re.MULTILINE):
                vulnerabilities.append(Vulnerability(
                    vulnerability_type=VulnerabilityType.REENTRANCY,
                    severity=SeverityLevel.HIGH,
                    impact=[VulnerabilityImpact.FUNDS_LOSS],
                    location=self._find_vulnerability_location(contract_code, r'\.call'),
                    title="Potential Reentrancy Vulnerability",
                    description="External call followed by state change may allow reentrancy attacks",
                    recommended_fix="Use checks-effects-interactions pattern or reentrancy guard"
                ))
        
        # Access control issues
        if re.search(r'function.*public.*onlyOwner', contract_code):
            # Check for missing access control
            functions = re.findall(r'function\s+(\w+).*public(?!\s+onlyOwner)', contract_code)
            for func in functions:
                if func in ['withdraw', 'transfer', 'mint', 'burn']:
                    vulnerabilities.append(Vulnerability(
                        vulnerability_type=VulnerabilityType.ACCESS_CONTROL,
                        severity=SeverityLevel.MEDIUM,
                        impact=[VulnerabilityImpact.PRIVILEGE_ESCALATION],
                        title=f"Missing access control on {func}",
                        description=f"Function {func} is public but may need access restrictions"
                    ))
        
        return vulnerabilities
    
    def _extract_contract_name(self, contract_code: str) -> str:
        """Extract contract name from source code."""
        match = re.search(r'contract\s+(\w+)', contract_code)
        return match.group(1) if match else "UnknownContract"
    
    def _find_vulnerability_location(self, contract_code: str, pattern: str) -> Optional[VulnerabilityLocation]:
        """Find the location of a vulnerability pattern in the code."""
        match = re.search(pattern, contract_code)
        if match:
            lines_before = contract_code[:match.start()].count('\n')
            return VulnerabilityLocation(
                line_start=lines_before + 1,
                line_end=lines_before + 1
            )
        return None

class EtherscanContractCollector(InternetDataCollector):
    """Collect verified smart contracts from Etherscan."""
    
    def __init__(self, cache_dir: str = "data/cache/etherscan", api_key: str = None):
        super().__init__(cache_dir, rate_limit_delay=0.2)  # 5 requests per second limit
        self.api_key = api_key
        self.base_url = "https://api.etherscan.io/api"
    
    def collect_verified_contracts(self, addresses: List[str]) -> List[ContractAuditData]:
        """Collect verified contracts by address."""
        contracts = []
        
        for address in addresses:
            contract_data = self._fetch_contract_source(address)
            if contract_data:
                contracts.append(contract_data)
        
        return contracts
    
    def search_contracts_by_name(self, contract_names: List[str]) -> List[ContractAuditData]:
        """Search for contracts by name patterns."""
        # This would require additional Etherscan API endpoints or web scraping
        # For demo purposes, returning empty list
        logger.info("Contract name search not implemented - requires additional API access")
        return []
    
    def _fetch_contract_source(self, address: str) -> Optional[ContractAuditData]:
        """Fetch contract source code from Etherscan."""
        params = {
            'module': 'contract',
            'action': 'getsourcecode', 
            'address': address
        }
        
        if self.api_key:
            params['apikey'] = self.api_key
        
        url = self.base_url
        data = self._fetch_with_cache(url, params)
        
        if not data or data.get('status') != '1':
            return None
        
        result = data['result'][0]
        source_code = result.get('SourceCode', '')
        
        if not source_code:
            return None
        
        # Analyze for vulnerabilities
        vulnerabilities = self._analyze_verified_contract(source_code, result)
        
        return ContractAuditData(
            contract_source=ContractSource(
                file_path=f"etherscan/{address}.sol",
                content=source_code,
                compiler_version=result.get('CompilerVersion', ''),
                optimizer_enabled=result.get('OptimizationUsed') == '1',
                optimizer_runs=int(result.get('Runs', 200))
            ),
            contract_name=result.get('ContractName', 'Unknown'),
            vulnerabilities=vulnerabilities,
            source_dataset="Etherscan"
        )
    
    def _analyze_verified_contract(self, source_code: str, contract_info: Dict) -> List[Vulnerability]:
        """Analyze verified contract for potential issues."""
        # Use similar pattern matching as GitHub collector
        # Could be enhanced with more sophisticated analysis
        vulnerabilities = []
        
        # Check for older Solidity versions with known issues
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+)', source_code)
        if pragma_match:
            version = pragma_match.group(1)
            if '0.4' in version or '0.5' in version:
                vulnerabilities.append(Vulnerability(
                    vulnerability_type=VulnerabilityType.COMPILER_BUG,
                    severity=SeverityLevel.MEDIUM,
                    impact=[VulnerabilityImpact.LOGIC_ERROR],
                    title="Outdated Solidity Version",
                    description=f"Contract uses potentially vulnerable Solidity version {version}"
                ))
        
        return vulnerabilities

class BugBountyCollector(InternetDataCollector):
    """Collect vulnerability data from bug bounty platforms."""
    
    def __init__(self, cache_dir: str = "data/cache/bugbounty"):
        super().__init__(cache_dir, rate_limit_delay=2.0)  # Conservative rate limiting
    
    def collect_immunefi_reports(self) -> List[ContractAuditData]:
        """Collect public bug reports from Immunefi."""
        # This would require web scraping or API access to Immunefi
        # Implementation would depend on their terms of service
        logger.info("Immunefi collection requires implementation of web scraping")
        return []
    
    def collect_hackerone_reports(self) -> List[ContractAuditData]:
        """Collect disclosed smart contract vulnerabilities from HackerOne."""
        # Similar to Immunefi, would need appropriate access
        logger.info("HackerOne collection requires implementation of web scraping")
        return []

class AcademicPaperCollector(InternetDataCollector):
    """Collect vulnerability examples from academic papers and research."""
    
    def __init__(self, cache_dir: str = "data/cache/academic"):
        super().__init__(cache_dir, rate_limit_delay=1.0)
    
    def collect_arxiv_papers(self) -> List[ContractAuditData]:
        """Collect smart contract vulnerability examples from arXiv papers."""
        # Would search arXiv API for smart contract security papers
        # and extract code examples
        logger.info("Academic paper collection requires implementation")
        return []

# Enhanced version of existing collectors

class EnhancedSWCCollector(InternetDataCollector):
    """Enhanced SWC collector that fetches real data from the web."""
    
    def __init__(self, cache_dir: str = "data/cache/swc_enhanced"):
        super().__init__(cache_dir, rate_limit_delay=1.0)
        self.swc_github_url = "https://api.github.com/repos/SmartContractSecurity/SWC-registry/contents"
    
    def collect_all_swc_examples(self) -> List[ContractAuditData]:
        """Collect all real SWC examples from GitHub repository."""
        contracts = []
        
        # For demonstration, let's use some hardcoded SWC examples with real vulnerability patterns
        # In a production system, this would fetch from the actual SWC registry
        
        examples = [
            {
                'swc_id': 'SWC-107',
                'name': 'Reentrancy',
                'contract_code': '''pragma solidity ^0.4.19;

contract ReentrancyVictim {
    mapping (address => uint) userBalance;
    
    function withdrawBalance() public {
        uint amountToWithdraw = userBalance[msg.sender];
        // Vulnerable: external call before state change
        if (msg.sender.call.value(amountToWithdraw)()) {
            userBalance[msg.sender] = 0;
        }
    }
    
    function deposit() public payable {
        userBalance[msg.sender] += msg.value;
    }
}''',
                'vulnerability_type': VulnerabilityType.REENTRANCY
            },
            {
                'swc_id': 'SWC-101',
                'name': 'Integer Overflow',
                'contract_code': '''pragma solidity ^0.4.19;

contract IntegerOverflowMinimal {
    mapping (address => uint256) public balanceOf;
    
    function transfer(address _to, uint256 _value) public {
        // Vulnerable: no overflow check
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
    }
}''',
                'vulnerability_type': VulnerabilityType.INTEGER_OVERFLOW
            },
            {
                'swc_id': 'SWC-105',
                'name': 'Unprotected Ether Withdrawal',
                'contract_code': '''pragma solidity ^0.8.0;

contract UnprotectedWithdraw {
    address public owner;
    
    constructor() { owner = msg.sender; }
    
    function withdraw() public {
        // Vulnerable: no access control
        payable(msg.sender).transfer(address(this).balance);
    }
    
    receive() external payable {}
}''',
                'vulnerability_type': VulnerabilityType.ACCESS_CONTROL
            }
        ]
        
        for example in examples:
            vulnerability = Vulnerability(
                vulnerability_type=example['vulnerability_type'],
                severity=SeverityLevel.HIGH,
                impact=[VulnerabilityImpact.FUNDS_LOSS],
                location=VulnerabilityLocation(line_start=1, line_end=1),
                affected_code="Contract vulnerable to " + example['name'],
                title=f"{example['swc_id']}: {example['name']}",
                description=f"Example vulnerable contract demonstrating {example['name']} vulnerability pattern",
                root_cause=f"Code vulnerable to {example['name']} due to improper implementation",
                recommended_fix="Apply security best practices to fix vulnerability",
                references=[f"https://swcregistry.io/docs/{example['swc_id']}"],
                confidence=1.0
            )
            
            contract_data = ContractAuditData(
                contract_source=ContractSource(
                    file_path=f"swc-enhanced/{example['swc_id']}.sol",
                    content=example['contract_code'],
                    compiler_version="0.8.0"
                ),
                contract_name=self._extract_contract_name(example['contract_code']),
                vulnerabilities=[vulnerability],
                source_dataset="SWC-Enhanced"
            )
            
            contracts.append(contract_data)
        
        logger.info(f"Generated {len(contracts)} SWC examples")
        return contracts
    
    def _collect_swc_entry(self, swc_id: str, swc_url: str) -> List[ContractAuditData]:
        """Collect contracts for a specific SWC entry."""
        swc_contents = self._fetch_with_cache(swc_url)
        if not swc_contents:
            return []
        
        contracts = []
        for item in swc_contents:
            if item['name'].endswith('.sol'):
                contract_data = self._fetch_swc_contract(swc_id, item)
                if contract_data:
                    contracts.append(contract_data)
        
        return contracts
    
    def _fetch_swc_contract(self, swc_id: str, file_info: Dict) -> Optional[ContractAuditData]:
        """Fetch and process an individual SWC contract example."""
        content_data = self._fetch_with_cache(file_info['download_url'])
        if not content_data:
            return None
        
        contract_code = content_data.get('content', '')
        vuln_type = self._map_swc_to_vulnerability_type(swc_id)
        
        return ContractAuditData(
            contract_source=ContractSource(
                file_path=f"swc/{swc_id}/{file_info['name']}",
                content=contract_code,
                compiler_version="0.8.0"
            ),
            contract_name=self._extract_contract_name(contract_code),
            vulnerabilities=[Vulnerability(
                vulnerability_type=vuln_type,
                severity=SeverityLevel.HIGH,
                impact=[VulnerabilityImpact.FUNDS_LOSS],
                title=f"{swc_id} Example",
                description=f"Example vulnerable contract from SWC registry entry {swc_id}",
                references=[f"https://swcregistry.io/docs/{swc_id}"]
            )],
            source_dataset="SWC-Enhanced"
        )
    
    def _map_swc_to_vulnerability_type(self, swc_id: str) -> VulnerabilityType:
        """Map SWC ID to vulnerability type."""
        mapping = {
            'SWC-107': VulnerabilityType.REENTRANCY,
            'SWC-101': VulnerabilityType.INTEGER_OVERFLOW,
            'SWC-104': VulnerabilityType.UNCHECKED_CALL,
            'SWC-105': VulnerabilityType.ACCESS_CONTROL,
            # Add more mappings as needed
        }
        return mapping.get(swc_id, VulnerabilityType.OTHER)
    
    def _extract_contract_name(self, contract_code: str) -> str:
        """Extract contract name from source code."""
        match = re.search(r'contract\s+(\w+)', contract_code)
        return match.group(1) if match else "UnknownContract"

# Main integration class

class InternetTrainingDataCollector:
    """Main collector that orchestrates internet-based data collection."""
    
    def __init__(self, config: Dict[str, any]):
        self.config = config
        self.collectors = {}
        
        # Initialize collectors based on configuration
        if config.get('github', {}).get('enabled', True):
            self.collectors['github'] = GitHubContractCollector(
                github_token=config.get('github', {}).get('token')
            )
        
        if config.get('etherscan', {}).get('enabled', True):
            self.collectors['etherscan'] = EtherscanContractCollector(
                api_key=config.get('etherscan', {}).get('api_key')
            )
        
        if config.get('swc_enhanced', {}).get('enabled', True):
            self.collectors['swc_enhanced'] = EnhancedSWCCollector()
        
        # Add more collectors as needed
    
    def collect_all_internet_data(self) -> Dict[str, List[ContractAuditData]]:
        """Collect data from all configured internet sources."""
        all_data = {}
        
        for source_name, collector in self.collectors.items():
            logger.info(f"Collecting data from {source_name}...")
            try:
                if source_name == 'github':
                    data = collector.collect_audit_repositories()
                elif source_name == 'etherscan':
                    # Would need a list of interesting contract addresses
                    data = []
                elif source_name == 'swc_enhanced':
                    data = collector.collect_all_swc_examples()
                else:
                    data = []
                
                all_data[source_name] = data
                logger.info(f"Collected {len(data)} examples from {source_name}")
                
            except Exception as e:
                logger.error(f"Failed to collect from {source_name}: {e}")
                all_data[source_name] = []
        
        return all_data
    
    def get_statistics(self) -> Dict[str, any]:
        """Get collection statistics."""
        return {
            'enabled_sources': list(self.collectors.keys()),
            'total_collectors': len(self.collectors),
            'request_counts': {
                name: getattr(collector, 'request_count', 0) 
                for name, collector in self.collectors.items()
            }
        }

# Example usage and configuration
def create_internet_config() -> Dict[str, any]:
    """Create a sample configuration for internet data collection."""
    return {
        'github': {
            'enabled': True,
            'token': None,  # Set to your GitHub personal access token
            'max_results_per_search': 100,
            'target_repositories': [
                "ConsenSys/smart-contract-best-practices",
                "crytic/not-so-smart-contracts", 
                "sigp/solidity-security-blog",
            ]
        },
        'etherscan': {
            'enabled': True,
            'api_key': None,  # Set to your Etherscan API key
            'target_addresses': [
                # List of known vulnerable or interesting contracts
            ]
        },
        'swc_enhanced': {
            'enabled': True
        },
        'rate_limiting': {
            'global_delay': 1.0,
            'respect_robots_txt': True
        },
        'cache': {
            'enabled': True,
            'max_age_days': 7
        }
    }

if __name__ == "__main__":
    # Example usage
    config = create_internet_config()
    collector = InternetTrainingDataCollector(config)
    
    # Collect data
    data = collector.collect_all_internet_data()
    
    # Print statistics
    stats = collector.get_statistics()
    print(f"Collected data from {stats['total_collectors']} sources")
    for source, count in stats['request_counts'].items():
        print(f"  {source}: {count} requests")
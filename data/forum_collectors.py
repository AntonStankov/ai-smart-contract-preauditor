"""
Forum and Web Search Collectors for Smart Contract Security Learning

This module collects vulnerability information from:
- Reddit (r/ethereum, r/solidity, r/ethdev)
- Security forums (Ethereum Stack Exchange, etc.)
- Web searches for vulnerability discussions
- Security blog posts and articles
"""

import re
import time
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import urljoin, quote
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
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    HAS_BS4 = False

from .schema import (
    ContractAuditData, ContractSource, Vulnerability, VulnerabilityLocation,
    VulnerabilityType, SeverityLevel, VulnerabilityImpact
)

logger = logging.getLogger(__name__)


class ForumDataCollector:
    """Base class for collecting data from forums and discussion platforms."""
    
    def __init__(self, cache_dir: str, rate_limit_delay: float = 2.0):
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
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Educational Research)',
            'Accept': 'text/html,application/json',
        })
        
        return session
    
    def _rate_limit(self):
        """Implement rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
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
            return None
        
        cache_path = self._get_cache_path(url)
        
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
        
        try:
            self._rate_limit()
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = {'content': response.text, 'url': url, 'status_code': response.status_code}
            
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return data
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None


class RedditCollector(ForumDataCollector):
    """Collect smart contract security discussions from Reddit."""
    
    def __init__(self, cache_dir: str = "data/cache/reddit"):
        super().__init__(cache_dir, rate_limit_delay=2.0)
        self.base_url = "https://www.reddit.com"
        self.api_url = "https://www.reddit.com/r"
    
    def collect_security_discussions(self, subreddits: List[str] = None, max_posts: int = 100) -> List[Dict]:
        """Collect posts from security-related subreddits."""
        if subreddits is None:
            subreddits = ['ethereum', 'solidity', 'ethdev', 'ethtrader', 'defi']
        
        all_posts = []
        
        for subreddit in subreddits:
            logger.info(f"Collecting from r/{subreddit}...")
            posts = self._collect_subreddit_posts(subreddit, max_posts // len(subreddits))
            all_posts.extend(posts)
        
        return all_posts
    
    def _collect_subreddit_posts(self, subreddit: str, max_posts: int) -> List[Dict]:
        """Collect posts from a specific subreddit."""
        posts = []
        url = f"{self.api_url}/{subreddit}/hot.json"
        
        params = {'limit': min(100, max_posts)}
        data = self._fetch_with_cache(url, params)
        
        if not data or 'content' not in data:
            return posts
        
        try:
            # Parse JSON response
            response_data = json.loads(data['content'])
            if 'data' in response_data and 'children' in response_data['data']:
                for child in response_data['data']['children']:
                    post_data = child.get('data', {})
                    if self._is_security_related(post_data):
                        posts.append({
                            'title': post_data.get('title', ''),
                            'selftext': post_data.get('selftext', ''),
                            'url': post_data.get('url', ''),
                            'score': post_data.get('score', 0),
                            'num_comments': post_data.get('num_comments', 0),
                            'subreddit': subreddit,
                            'created_utc': post_data.get('created_utc', 0)
                        })
        except Exception as e:
            logger.error(f"Failed to parse Reddit data: {e}")
        
        return posts[:max_posts]
    
    def _is_security_related(self, post_data: Dict) -> bool:
        """Check if post is related to security vulnerabilities."""
        title = post_data.get('title', '').lower()
        text = post_data.get('selftext', '').lower()
        
        security_keywords = [
            'vulnerability', 'exploit', 'hack', 'bug', 'security', 'audit',
            'reentrancy', 'overflow', 'access control', 'gas', 'dos',
            'flashloan', 'frontrun', 'mev', 'sandwich', 'attack'
        ]
        
        combined_text = f"{title} {text}"
        return any(keyword in combined_text for keyword in security_keywords)
    
    def extract_vulnerability_examples(self, posts: List[Dict]) -> List[ContractAuditData]:
        """Extract contract code and vulnerability information from Reddit posts."""
        examples = []
        
        for post in posts:
            # Extract Solidity code blocks
            code_blocks = self._extract_code_blocks(post['selftext'] + ' ' + post['title'])
            
            for code in code_blocks:
                if self._is_solidity_code(code):
                    vulnerabilities = self._analyze_discussion_for_vulnerabilities(
                        code, post['title'], post['selftext']
                    )
                    
                    if vulnerabilities:
                        contract_data = ContractAuditData(
                            contract_source=ContractSource(
                                file_path=f"reddit/{post['subreddit']}/{hashlib.md5(post['url'].encode()).hexdigest()}.sol",
                                content=code,
                                compiler_version="0.8.0"
                            ),
                            contract_name=self._extract_contract_name(code),
                            vulnerabilities=vulnerabilities,
                            source_dataset=f"Reddit-{post['subreddit']}"
                        )
                        examples.append(contract_data)
        
        return examples
    
    def _extract_code_blocks(self, text: str) -> List[str]:
        """Extract code blocks from markdown text."""
        code_blocks = []
        
        # Extract ```solidity blocks
        pattern = r'```(?:solidity)?\s*\n(.*?)```'
        matches = re.findall(pattern, text, re.DOTALL)
        code_blocks.extend(matches)
        
        # Extract inline code that looks like contracts
        pattern = r'`([^`]{50,})`'
        matches = re.findall(pattern, text)
        code_blocks.extend([m for m in matches if 'contract' in m or 'function' in m])
        
        return code_blocks
    
    def _is_solidity_code(self, code: str) -> bool:
        """Check if code looks like Solidity."""
        solidity_indicators = ['pragma solidity', 'contract ', 'function ', 'mapping(', 'address', 'uint']
        return any(indicator in code for indicator in solidity_indicators)
    
    def _extract_contract_name(self, code: str) -> str:
        """Extract contract name from code."""
        match = re.search(r'contract\s+(\w+)', code)
        return match.group(1) if match else "RedditContract"
    
    def _analyze_discussion_for_vulnerabilities(self, code: str, title: str, discussion: str) -> List[Vulnerability]:
        """Analyze discussion text to identify mentioned vulnerabilities."""
        vulnerabilities = []
        discussion_lower = (title + ' ' + discussion).lower()
        
        # Map discussion keywords to vulnerability types
        vuln_keywords = {
            VulnerabilityType.REENTRANCY: ['reentrancy', 'reentrant', 'call.value', 'external call'],
            VulnerabilityType.INTEGER_OVERFLOW: ['overflow', 'underflow', 'integer', 'arithmetic'],
            VulnerabilityType.ACCESS_CONTROL: ['access control', 'onlyowner', 'permission', 'authorization'],
            VulnerabilityType.UNCHECKED_CALL: ['unchecked', 'call return', 'call()'],
            VulnerabilityType.TX_ORIGIN: ['tx.origin', 'transaction origin'],
            VulnerabilityType.TIMESTAMP_DEPENDENCE: ['timestamp', 'block.timestamp', 'now'],
            VulnerabilityType.DOS_GAS_LIMIT: ['gas limit', 'dos', 'denial of service', 'unbounded loop'],
        }
        
        for vuln_type, keywords in vuln_keywords.items():
            if any(keyword in discussion_lower for keyword in keywords):
                # Find location in code
                location = self._find_vulnerability_in_code(code, vuln_type)
                
                vulnerability = Vulnerability(
                    vulnerability_type=vuln_type,
                    severity=self._estimate_severity_from_discussion(discussion_lower, vuln_type),
                    impact=[VulnerabilityImpact.FUNDS_LOSS],
                    location=location or VulnerabilityLocation(line_start=1, line_end=1),
                    affected_code=code[:200] + '...' if len(code) > 200 else code,
                    title=f"{vuln_type.value} - From Discussion",
                    description=f"Vulnerability mentioned in discussion: {title[:100]}",
                    root_cause=self._extract_root_cause_from_discussion(discussion, vuln_type),
                    recommended_fix=self._extract_fix_from_discussion(discussion, vuln_type),
                    confidence=0.7
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _find_vulnerability_in_code(self, code: str, vuln_type: VulnerabilityType) -> Optional[VulnerabilityLocation]:
        """Find vulnerability location in code."""
        patterns = {
            VulnerabilityType.REENTRANCY: [r'\.call\{value:', r'\.call\(', r'\.transfer\('],
            VulnerabilityType.TX_ORIGIN: [r'tx\.origin'],
            VulnerabilityType.TIMESTAMP_DEPENDENCE: [r'block\.timestamp', r'\bnow\b'],
        }
        
        for pattern in patterns.get(vuln_type, []):
            match = re.search(pattern, code)
            if match:
                lines_before = code[:match.start()].count('\n')
                return VulnerabilityLocation(line_start=lines_before + 1, line_end=lines_before + 1)
        
        return None
    
    def _estimate_severity_from_discussion(self, discussion: str, vuln_type: VulnerabilityType) -> SeverityLevel:
        """Estimate severity from discussion context."""
        if 'critical' in discussion or 'exploit' in discussion or 'hack' in discussion:
            return SeverityLevel.CRITICAL
        elif 'high' in discussion or 'serious' in discussion:
            return SeverityLevel.HIGH
        elif 'medium' in discussion or 'moderate' in discussion:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _extract_root_cause_from_discussion(self, discussion: str, vuln_type: VulnerabilityType) -> str:
        """Extract root cause explanation from discussion."""
        # Look for explanations in the discussion
        sentences = re.split(r'[.!?]\s+', discussion)
        for sentence in sentences:
            if any(word in sentence.lower() for word in ['because', 'due to', 'caused by', 'reason']):
                if len(sentence) > 20 and len(sentence) < 200:
                    return sentence.strip()
        
        return f"Vulnerability pattern identified from community discussion"
    
    def _extract_fix_from_discussion(self, discussion: str, vuln_type: VulnerabilityType) -> str:
        """Extract fix recommendations from discussion."""
        sentences = re.split(r'[.!?]\s+', discussion)
        for sentence in sentences:
            if any(word in sentence.lower() for word in ['fix', 'solution', 'should', 'recommend', 'use']):
                if len(sentence) > 20 and len(sentence) < 200:
                    return sentence.strip()
        
        return "Apply security best practices based on vulnerability type"


class WebSearchCollector(ForumDataCollector):
    """Collect vulnerability information from web searches."""
    
    def __init__(self, cache_dir: str = "data/cache/websearch"):
        super().__init__(cache_dir, rate_limit_delay=3.0)
    
    def search_vulnerability_discussions(self, queries: List[str] = None, max_results: int = 50) -> List[Dict]:
        """Search the web for vulnerability discussions."""
        if queries is None:
            queries = [
                "solidity reentrancy vulnerability example",
                "smart contract integer overflow exploit",
                "ethereum access control bug",
                "defi flashloan attack code",
                "solidity security best practices",
                "smart contract audit findings",
                "ethereum vulnerability disclosure"
            ]
        
        all_results = []
        
        for query in queries:
            logger.info(f"Searching for: {query}")
            results = self._search_duckduckgo(query, max_results // len(queries))
            all_results.extend(results)
            time.sleep(2)  # Be respectful with searches
        
        return all_results
    
    def _search_duckduckgo(self, query: str, max_results: int) -> List[Dict]:
        """Search using DuckDuckGo (no API key required)."""
        try:
            from duckduckgo_search import DDGS
            with DDGS() as ddgs:
                results = []
                for result in ddgs.text(query, max_results=max_results):
                    results.append({
                        'title': result.get('title', ''),
                        'url': result.get('href', ''),
                        'snippet': result.get('body', '')
                    })
                return results
        except ImportError:
            logger.warning("duckduckgo_search not installed, using fallback")
            return self._search_fallback(query, max_results)
        except Exception as e:
            logger.error(f"DuckDuckGo search failed: {e}")
            return []
    
    def _search_fallback(self, query: str, max_results: int) -> List[Dict]:
        """Fallback search method."""
        # This would use a different search method or return cached results
        logger.info("Using fallback search (limited results)")
        return []
    
    def extract_vulnerability_data(self, search_results: List[Dict]) -> List[ContractAuditData]:
        """Extract vulnerability examples from search results."""
        examples = []
        
        for result in search_results:
            # Fetch the actual page content
            page_data = self._fetch_with_cache(result['url'])
            if not page_data:
                continue
            
            content = page_data.get('content', '')
            if not content:
                continue
            
            # Extract code blocks and vulnerability information
            code_blocks = self._extract_code_from_html(content)
            
            for code in code_blocks:
                if self._is_solidity_code(code):
                    vulnerabilities = self._analyze_content_for_vulnerabilities(
                        code, result['title'], result['snippet']
                    )
                    
                    if vulnerabilities:
                        contract_data = ContractAuditData(
                            contract_source=ContractSource(
                                file_path=f"websearch/{hashlib.md5(result['url'].encode()).hexdigest()}.sol",
                                content=code,
                                compiler_version="0.8.0"
                            ),
                            contract_name=self._extract_contract_name(code),
                            vulnerabilities=vulnerabilities,
                            source_dataset="WebSearch"
                        )
                        examples.append(contract_data)
        
        return examples
    
    def _extract_code_from_html(self, html: str) -> List[str]:
        """Extract code blocks from HTML content."""
        code_blocks = []
        
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                # Find <pre><code> blocks
                for code_tag in soup.find_all(['code', 'pre']):
                    text = code_tag.get_text()
                    if self._is_solidity_code(text):
                        code_blocks.append(text)
            except Exception as e:
                logger.error(f"Failed to parse HTML: {e}")
        
        # Also try regex extraction
        pattern = r'<pre[^>]*><code[^>]*>(.*?)</code></pre>'
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        code_blocks.extend(matches)
        
        return code_blocks
    
    def _is_solidity_code(self, code: str) -> bool:
        """Check if code looks like Solidity."""
        solidity_indicators = ['pragma solidity', 'contract ', 'function ', 'mapping(']
        return any(indicator in code for indicator in solidity_indicators)
    
    def _extract_contract_name(self, code: str) -> str:
        """Extract contract name."""
        match = re.search(r'contract\s+(\w+)', code)
        return match.group(1) if match else "WebContract"
    
    def _analyze_content_for_vulnerabilities(self, code: str, title: str, snippet: str) -> List[Vulnerability]:
        """Analyze content for vulnerability mentions."""
        # Similar to Reddit collector
        vulnerabilities = []
        text_lower = (title + ' ' + snippet).lower()
        
        vuln_keywords = {
            VulnerabilityType.REENTRANCY: ['reentrancy', 'reentrant'],
            VulnerabilityType.INTEGER_OVERFLOW: ['overflow', 'underflow'],
            VulnerabilityType.ACCESS_CONTROL: ['access control', 'authorization'],
        }
        
        for vuln_type, keywords in vuln_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                vulnerability = Vulnerability(
                    vulnerability_type=vuln_type,
                    severity=SeverityLevel.HIGH,
                    impact=[VulnerabilityImpact.FUNDS_LOSS],
                    location=VulnerabilityLocation(line_start=1, line_end=1),
                    affected_code=code[:200],
                    title=f"{vuln_type.value} from Web Search",
                    description=f"Found in: {title}",
                    root_cause="Identified from web search results",
                    recommended_fix="Apply security best practices",
                    confidence=0.6
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities


class StackOverflowCollector(ForumDataCollector):
    """Collect smart contract security discussions from Stack Overflow."""
    
    def __init__(self, cache_dir: str = "data/cache/stackoverflow", api_key: str = None):
        super().__init__(cache_dir, rate_limit_delay=0.1)  # Stack Overflow allows 300 requests/day
        self.api_key = api_key
        self.base_url = "https://api.stackexchange.com/2.3"
    
    def collect_security_questions(self, tags: List[str] = None, max_questions: int = 100) -> List[Dict]:
        """Collect questions tagged with Solidity and security-related tags."""
        if tags is None:
            tags = ['solidity', 'ethereum', 'smart-contracts', 'web3']
        
        all_questions = []
        
        for tag in tags:
            logger.info(f"Collecting Stack Overflow questions tagged '{tag}'...")
            questions = self._search_questions(tag, max_questions // len(tags))
            all_questions.extend(questions)
        
        return all_questions[:max_questions]
    
    def _search_questions(self, tag: str, max_questions: int) -> List[Dict]:
        """Search for questions with a specific tag."""
        url = f"{self.base_url}/questions"
        params = {
            'order': 'desc',
            'sort': 'activity',
            'tagged': tag,
            'site': 'stackoverflow',
            'filter': 'withbody',
            'pagesize': min(100, max_questions)
        }
        
        if self.api_key:
            params['key'] = self.api_key
        
        data = self._fetch_with_cache(url, params)
        questions = []
        
        if data and 'content' in data:
            try:
                response_data = json.loads(data['content'])
                if 'items' in response_data:
                    for item in response_data['items']:
                        if self._is_security_related(item):
                            questions.append({
                                'title': item.get('title', ''),
                                'body': item.get('body', ''),
                                'question_id': item.get('question_id', ''),
                                'score': item.get('score', 0),
                                'answers': item.get('answer_count', 0),
                                'tags': item.get('tags', []),
                                'url': item.get('link', ''),
                                'created_date': item.get('creation_date', 0)
                            })
            except Exception as e:
                logger.error(f"Failed to parse Stack Overflow data: {e}")
        
        return questions[:max_questions]
    
    def _is_security_related(self, question: Dict) -> bool:
        """Check if question is security-related."""
        title = question.get('title', '').lower()
        body = question.get('body', '').lower()
        tags = [t.lower() for t in question.get('tags', [])]
        
        security_keywords = [
            'vulnerability', 'exploit', 'hack', 'bug', 'security', 'audit',
            'reentrancy', 'overflow', 'access control', 'gas', 'dos',
            'flashloan', 'frontrun', 'mev', 'sandwich', 'attack', 'safe',
            'secure', 'risk', 'danger', 'exploit', 'breach'
        ]
        
        combined_text = f"{title} {body}"
        return any(keyword in combined_text for keyword in security_keywords) or \
               any(keyword in tags for keyword in ['security', 'vulnerability', 'audit'])
    
    def extract_vulnerability_examples(self, questions: List[Dict]) -> List[ContractAuditData]:
        """Extract vulnerability examples from Stack Overflow questions."""
        examples = []
        
        for question in questions:
            code_blocks = self._extract_code_blocks(question['body'] + ' ' + question['title'])
            
            for code in code_blocks:
                if self._is_solidity_code(code):
                    vulnerabilities = self._analyze_discussion_for_vulnerabilities(
                        code, question['title'], question['body']
                    )
                    
                    if vulnerabilities:
                        contract_data = ContractAuditData(
                            contract_source=ContractSource(
                                file_path=f"stackoverflow/{question['question_id']}.sol",
                                content=code,
                                compiler_version="0.8.0"
                            ),
                            contract_name=self._extract_contract_name(code),
                            vulnerabilities=vulnerabilities,
                            source_dataset="StackOverflow"
                        )
                        examples.append(contract_data)
        
        return examples
    
    def _extract_code_blocks(self, text: str) -> List[str]:
        """Extract code blocks from HTML text."""
        code_blocks = []
        
        # Stack Overflow uses <pre><code> blocks
        pattern = r'<pre><code>(.*?)</code></pre>'
        matches = re.findall(pattern, text, re.DOTALL)
        code_blocks.extend(matches)
        
        # Also try markdown-style code blocks
        pattern = r'```(?:solidity)?\s*\n(.*?)```'
        matches = re.findall(pattern, text, re.DOTALL)
        code_blocks.extend(matches)
        
        return code_blocks
    
    def _is_solidity_code(self, code: str) -> bool:
        """Check if code looks like Solidity."""
        solidity_indicators = ['pragma solidity', 'contract ', 'function ', 'mapping(']
        return any(indicator in code for indicator in solidity_indicators)
    
    def _extract_contract_name(self, code: str) -> str:
        """Extract contract name."""
        match = re.search(r'contract\s+(\w+)', code)
        return match.group(1) if match else "StackOverflowContract"
    
    def _analyze_discussion_for_vulnerabilities(self, code: str, title: str, body: str) -> List[Vulnerability]:
        """Analyze Stack Overflow discussion for vulnerabilities."""
        # Similar to Reddit collector
        vulnerabilities = []
        discussion_lower = (title + ' ' + body).lower()
        
        vuln_keywords = {
            VulnerabilityType.REENTRANCY: ['reentrancy', 'reentrant', 'call.value'],
            VulnerabilityType.INTEGER_OVERFLOW: ['overflow', 'underflow', 'integer'],
            VulnerabilityType.ACCESS_CONTROL: ['access control', 'onlyowner', 'permission'],
            VulnerabilityType.UNCHECKED_CALL: ['unchecked', 'call return'],
            VulnerabilityType.TX_ORIGIN: ['tx.origin'],
            VulnerabilityType.TIMESTAMP_DEPENDENCE: ['timestamp', 'block.timestamp'],
        }
        
        for vuln_type, keywords in vuln_keywords.items():
            if any(keyword in discussion_lower for keyword in keywords):
                location = self._find_vulnerability_in_code(code, vuln_type)
                
                vulnerability = Vulnerability(
                    vulnerability_type=vuln_type,
                    severity=self._estimate_severity_from_discussion(discussion_lower, vuln_type),
                    impact=[VulnerabilityImpact.FUNDS_LOSS],
                    location=location or VulnerabilityLocation(line_start=1, line_end=1),
                    affected_code=code[:200] + '...' if len(code) > 200 else code,
                    title=f"{vuln_type.value} - From Stack Overflow",
                    description=f"Vulnerability discussed in: {title[:100]}",
                    root_cause=self._extract_root_cause_from_discussion(body, vuln_type),
                    recommended_fix=self._extract_fix_from_discussion(body, vuln_type),
                    confidence=0.75
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _find_vulnerability_in_code(self, code: str, vuln_type: VulnerabilityType) -> Optional[VulnerabilityLocation]:
        """Find vulnerability location in code."""
        patterns = {
            VulnerabilityType.REENTRANCY: [r'\.call\{value:', r'\.call\(', r'\.transfer\('],
            VulnerabilityType.TX_ORIGIN: [r'tx\.origin'],
            VulnerabilityType.TIMESTAMP_DEPENDENCE: [r'block\.timestamp', r'\bnow\b'],
        }
        
        for pattern in patterns.get(vuln_type, []):
            match = re.search(pattern, code)
            if match:
                lines_before = code[:match.start()].count('\n')
                return VulnerabilityLocation(line_start=lines_before + 1, line_end=lines_before + 1)
        
        return None
    
    def _estimate_severity_from_discussion(self, discussion: str, vuln_type: VulnerabilityType) -> SeverityLevel:
        """Estimate severity from discussion."""
        if 'critical' in discussion or 'exploit' in discussion:
            return SeverityLevel.CRITICAL
        elif 'high' in discussion or 'serious' in discussion:
            return SeverityLevel.HIGH
        else:
            return SeverityLevel.MEDIUM
    
    def _extract_root_cause_from_discussion(self, discussion: str, vuln_type: VulnerabilityType) -> str:
        """Extract root cause from discussion."""
        sentences = re.split(r'[.!?]\s+', discussion)
        for sentence in sentences:
            if any(word in sentence.lower() for word in ['because', 'due to', 'caused by']):
                if 20 < len(sentence) < 200:
                    return sentence.strip()
        return f"Vulnerability pattern identified from Stack Overflow discussion"
    
    def _extract_fix_from_discussion(self, discussion: str, vuln_type: VulnerabilityType) -> str:
        """Extract fix from discussion."""
        sentences = re.split(r'[.!?]\s+', discussion)
        for sentence in sentences:
            if any(word in sentence.lower() for word in ['fix', 'solution', 'should', 'use']):
                if 20 < len(sentence) < 200:
                    return sentence.strip()
        return "Apply security best practices based on vulnerability type"


class EthereumStackExchangeCollector(StackOverflowCollector):
    """Collect from Ethereum Stack Exchange (uses same API as Stack Overflow)."""
    
    def __init__(self, cache_dir: str = "data/cache/ethereum_se", api_key: str = None):
        super().__init__(cache_dir, api_key)
        self.base_url = "https://api.stackexchange.com/2.3"
    
    def _search_questions(self, tag: str, max_questions: int) -> List[Dict]:
        """Search Ethereum Stack Exchange questions."""
        url = f"{self.base_url}/questions"
        params = {
            'order': 'desc',
            'sort': 'activity',
            'tagged': tag,
            'site': 'ethereum',  # Ethereum Stack Exchange
            'filter': 'withbody',
            'pagesize': min(100, max_questions)
        }
        
        if self.api_key:
            params['key'] = self.api_key
        
        data = self._fetch_with_cache(url, params)
        questions = []
        
        if data and 'content' in data:
            try:
                response_data = json.loads(data['content'])
                if 'items' in response_data:
                    for item in response_data['items']:
                        if self._is_security_related(item):
                            questions.append({
                                'title': item.get('title', ''),
                                'body': item.get('body', ''),
                                'question_id': item.get('question_id', ''),
                                'score': item.get('score', 0),
                                'answers': item.get('answer_count', 0),
                                'tags': item.get('tags', []),
                                'url': item.get('link', ''),
                                'created_date': item.get('creation_date', 0)
                            })
            except Exception as e:
                logger.error(f"Failed to parse Ethereum SE data: {e}")
        
        return questions[:max_questions]


class HackerNewsCollector(ForumDataCollector):
    """Collect security discussions from Hacker News."""
    
    def __init__(self, cache_dir: str = "data/cache/hackernews"):
        super().__init__(cache_dir, rate_limit_delay=1.0)
        self.api_url = "https://hacker-news.firebaseio.com/v0"
    
    def collect_security_stories(self, max_stories: int = 100) -> List[Dict]:
        """Collect security-related stories from Hacker News."""
        logger.info("Collecting from Hacker News...")
        
        # Get top stories
        top_stories_url = f"{self.api_url}/topstories.json"
        data = self._fetch_with_cache(top_stories_url)
        
        if not data or 'content' not in data:
            return []
        
        try:
            story_ids = json.loads(data['content'])[:max_stories]
            stories = []
            
            for story_id in story_ids:
                story = self._fetch_story(story_id)
                if story and self._is_security_related(story):
                    stories.append(story)
                    if len(stories) >= max_stories:
                        break
            
            return stories
        except Exception as e:
            logger.error(f"Failed to parse Hacker News data: {e}")
            return []
    
    def _fetch_story(self, story_id: int) -> Optional[Dict]:
        """Fetch a single story from Hacker News."""
        url = f"{self.api_url}/item/{story_id}.json"
        data = self._fetch_with_cache(url)
        
        if not data or 'content' not in data:
            return None
        
        try:
            return json.loads(data['content'])
        except:
            return None
    
    def _is_security_related(self, story: Dict) -> bool:
        """Check if story is security-related."""
        title = story.get('title', '').lower()
        text = story.get('text', '').lower()
        url = story.get('url', '').lower()
        
        security_keywords = [
            'vulnerability', 'exploit', 'hack', 'bug', 'security', 'audit',
            'reentrancy', 'overflow', 'smart contract', 'ethereum', 'solidity',
            'defi', 'crypto', 'blockchain security'
        ]
        
        combined = f"{title} {text} {url}"
        return any(keyword in combined for keyword in security_keywords)
    
    def extract_vulnerability_examples(self, stories: List[Dict]) -> List[ContractAuditData]:
        """Extract vulnerability examples from Hacker News stories."""
        examples = []
        
        for story in stories:
            # Hacker News stories often link to articles with code examples
            # We'd need to fetch the linked article, but for now, extract from text
            text = story.get('text', '') + ' ' + story.get('title', '')
            code_blocks = self._extract_code_blocks(text)
            
            for code in code_blocks:
                if self._is_solidity_code(code):
                    vulnerabilities = self._analyze_for_vulnerabilities(code, story)
                    if vulnerabilities:
                        contract_data = ContractAuditData(
                            contract_source=ContractSource(
                                file_path=f"hackernews/{story.get('id', 'unknown')}.sol",
                                content=code,
                                compiler_version="0.8.0"
                            ),
                            contract_name=self._extract_contract_name(code),
                            vulnerabilities=vulnerabilities,
                            source_dataset="HackerNews"
                        )
                        examples.append(contract_data)
        
        return examples
    
    def _extract_code_blocks(self, text: str) -> List[str]:
        """Extract code blocks from text."""
        # Hacker News uses plain text, look for code-like patterns
        pattern = r'```(.*?)```'
        matches = re.findall(pattern, text, re.DOTALL)
        return [m for m in matches if 'contract' in m or 'function' in m]
    
    def _is_solidity_code(self, code: str) -> bool:
        """Check if code looks like Solidity."""
        return 'pragma solidity' in code or 'contract ' in code
    
    def _extract_contract_name(self, code: str) -> str:
        """Extract contract name."""
        match = re.search(r'contract\s+(\w+)', code)
        return match.group(1) if match else "HNContract"
    
    def _analyze_for_vulnerabilities(self, code: str, story: Dict) -> List[Vulnerability]:
        """Analyze for vulnerabilities."""
        vulnerabilities = []
        text = (story.get('title', '') + ' ' + story.get('text', '')).lower()
        
        if 'reentrancy' in text or 'reentrant' in text:
            vulnerabilities.append(Vulnerability(
                vulnerability_type=VulnerabilityType.REENTRANCY,
                severity=SeverityLevel.HIGH,
                impact=[VulnerabilityImpact.FUNDS_LOSS],
                location=VulnerabilityLocation(line_start=1, line_end=1),
                affected_code=code[:200],
                title="Reentrancy Vulnerability",
                description=f"From Hacker News: {story.get('title', '')[:100]}",
                root_cause="Identified from Hacker News discussion",
                recommended_fix="Apply security best practices",
                confidence=0.7
            ))
        
        return vulnerabilities


class MediumCollector(ForumDataCollector):
    """Collect security articles from Medium."""
    
    def __init__(self, cache_dir: str = "data/cache/medium"):
        super().__init__(cache_dir, rate_limit_delay=2.0)
    
    def collect_security_articles(self, queries: List[str] = None, max_articles: int = 50) -> List[Dict]:
        """Search Medium for security articles."""
        if queries is None:
            queries = [
                "solidity security vulnerability",
                "smart contract audit",
                "ethereum exploit",
                "defi security"
            ]
        
        all_articles = []
        
        # Medium doesn't have a public API, so we use web search
        # In production, you might use RSS feeds or web scraping
        logger.info("Medium collection requires web search integration")
        
        return all_articles
    
    def extract_vulnerability_examples(self, articles: List[Dict]) -> List[ContractAuditData]:
        """Extract examples from Medium articles."""
        # Similar to web search collector
        examples = []
        # Implementation would parse Medium article HTML
        return examples


class ForumTrainingDataCollector:
    """Main collector that orchestrates forum and web search data collection."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Initialize all collectors
        self.reddit_collector = RedditCollector(
            cache_dir=self.config.get('reddit_cache', 'data/cache/reddit')
        )
        self.web_collector = WebSearchCollector(
            cache_dir=self.config.get('web_cache', 'data/cache/websearch')
        )
        self.stackoverflow_collector = StackOverflowCollector(
            cache_dir=self.config.get('stackoverflow_cache', 'data/cache/stackoverflow'),
            api_key=self.config.get('stackoverflow_api_key')
        )
        self.ethereum_se_collector = EthereumStackExchangeCollector(
            cache_dir=self.config.get('ethereum_se_cache', 'data/cache/ethereum_se'),
            api_key=self.config.get('stackoverflow_api_key')  # Same API key
        )
        self.hackernews_collector = HackerNewsCollector(
            cache_dir=self.config.get('hackernews_cache', 'data/cache/hackernews')
        )
        self.medium_collector = MediumCollector(
            cache_dir=self.config.get('medium_cache', 'data/cache/medium')
        )
    
    def collect_all_forum_data(self) -> List[ContractAuditData]:
        """Collect data from all forum sources."""
        all_examples = []
        
        # Collect from Reddit
        if self.config.get('reddit', {}).get('enabled', True):
            logger.info("Collecting from Reddit...")
            try:
                posts = self.reddit_collector.collect_security_discussions(
                    max_posts=self.config.get('reddit', {}).get('max_posts', 100)
                )
                reddit_examples = self.reddit_collector.extract_vulnerability_examples(posts)
                all_examples.extend(reddit_examples)
                logger.info(f"Collected {len(reddit_examples)} examples from Reddit")
            except Exception as e:
                logger.error(f"Reddit collection failed: {e}")
        
        # Collect from Stack Overflow
        if self.config.get('stackoverflow', {}).get('enabled', True):
            logger.info("Collecting from Stack Overflow...")
            try:
                questions = self.stackoverflow_collector.collect_security_questions(
                    max_questions=self.config.get('stackoverflow', {}).get('max_questions', 100)
                )
                so_examples = self.stackoverflow_collector.extract_vulnerability_examples(questions)
                all_examples.extend(so_examples)
                logger.info(f"Collected {len(so_examples)} examples from Stack Overflow")
            except Exception as e:
                logger.error(f"Stack Overflow collection failed: {e}")
        
        # Collect from Ethereum Stack Exchange
        if self.config.get('ethereum_se', {}).get('enabled', True):
            logger.info("Collecting from Ethereum Stack Exchange...")
            try:
                questions = self.ethereum_se_collector.collect_security_questions(
                    max_questions=self.config.get('ethereum_se', {}).get('max_questions', 100)
                )
                ethereum_se_examples = self.ethereum_se_collector.extract_vulnerability_examples(questions)
                all_examples.extend(ethereum_se_examples)
                logger.info(f"Collected {len(ethereum_se_examples)} examples from Ethereum SE")
            except Exception as e:
                logger.error(f"Ethereum SE collection failed: {e}")
        
        # Collect from Hacker News
        if self.config.get('hackernews', {}).get('enabled', True):
            logger.info("Collecting from Hacker News...")
            try:
                stories = self.hackernews_collector.collect_security_stories(
                    max_stories=self.config.get('hackernews', {}).get('max_stories', 50)
                )
                hn_examples = self.hackernews_collector.extract_vulnerability_examples(stories)
                all_examples.extend(hn_examples)
                logger.info(f"Collected {len(hn_examples)} examples from Hacker News")
            except Exception as e:
                logger.error(f"Hacker News collection failed: {e}")
        
        # Collect from web search
        if self.config.get('web_search', {}).get('enabled', True):
            logger.info("Collecting from web searches...")
            try:
                search_results = self.web_collector.search_vulnerability_discussions(
                    max_results=self.config.get('web_search', {}).get('max_results', 50)
                )
                web_examples = self.web_collector.extract_vulnerability_data(search_results)
                all_examples.extend(web_examples)
                logger.info(f"Collected {len(web_examples)} examples from web search")
            except Exception as e:
                logger.error(f"Web search collection failed: {e}")
        
        return all_examples


def create_forum_config() -> Dict:
    """Create configuration for forum data collection."""
    return {
        'reddit': {
            'enabled': True,
            'max_posts': 200,
            'subreddits': ['ethereum', 'solidity', 'ethdev', 'ethtrader', 'defi']
        },
        'stackoverflow': {
            'enabled': True,
            'max_questions': 150,
            'tags': ['solidity', 'ethereum', 'smart-contracts', 'web3']
        },
        'ethereum_se': {
            'enabled': True,
            'max_questions': 100,
            'tags': ['solidity', 'security', 'vulnerability']
        },
        'hackernews': {
            'enabled': True,
            'max_stories': 50
        },
        'web_search': {
            'enabled': True,
            'max_results': 100,
            'queries': [
                "solidity reentrancy vulnerability",
                "smart contract security audit",
                "ethereum exploit code",
                "defi vulnerability disclosure",
                "solidity security best practices",
                "smart contract bug report",
                "ethereum vulnerability disclosure"
            ]
        },
        'stackoverflow_api_key': None,  # Optional: Get from https://stackapps.com/apps/oauth/register
        'reddit_cache': 'data/cache/reddit',
        'web_cache': 'data/cache/websearch',
        'stackoverflow_cache': 'data/cache/stackoverflow',
        'ethereum_se_cache': 'data/cache/ethereum_se',
        'hackernews_cache': 'data/cache/hackernews',
        'medium_cache': 'data/cache/medium'
    }


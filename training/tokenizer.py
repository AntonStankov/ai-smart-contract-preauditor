"""
Solidity-specific tokenization utilities for smart contract code.

This module provides enhanced tokenization for Solidity code that preserves
semantic meaning and handles contract-specific syntax patterns.
"""

import re
import ast
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from transformers import PreTrainedTokenizer, AutoTokenizer
import logging

logger = logging.getLogger(__name__)


@dataclass
class SolidityToken:
    """Enhanced token with Solidity-specific metadata."""
    text: str
    token_type: str
    line: int
    column: int
    is_identifier: bool = False
    is_keyword: bool = False
    is_function: bool = False
    is_modifier: bool = False
    is_literal: bool = False


class SolidityTokenizer:
    """Custom tokenizer for Solidity smart contracts."""
    
    # Solidity keywords
    KEYWORDS = {
        'abstract', 'after', 'alias', 'apply', 'auto', 'case', 'catch',
        'copyof', 'default', 'define', 'final', 'immutable', 'implements',
        'in', 'inline', 'let', 'macro', 'match', 'mutable', 'null', 'of',
        'override', 'partial', 'promise', 'reference', 'relocatable',
        'sealed', 'sizeof', 'static', 'supports', 'switch', 'try', 'type',
        'typeof', 'unchecked', 'pragma', 'import', 'contract', 'interface',
        'library', 'using', 'struct', 'enum', 'function', 'modifier',
        'event', 'constructor', 'receive', 'fallback', 'public', 'private',
        'internal', 'external', 'pure', 'view', 'payable', 'constant',
        'virtual', 'override', 'if', 'else', 'for', 'while', 'do', 'break',
        'continue', 'return', 'throw', 'revert', 'require', 'assert',
        'emit', 'new', 'delete', 'this', 'super', 'msg', 'tx', 'block',
        'gasleft', 'blockhash', 'now', 'true', 'false', 'wei', 'gwei',
        'ether', 'seconds', 'minutes', 'hours', 'days', 'weeks', 'years',
        'memory', 'storage', 'calldata', 'mapping', 'address', 'bool',
        'string', 'bytes', 'byte', 'uint', 'int', 'fixed', 'ufixed'
    }
    
    # Solidity operators and symbols
    OPERATORS = {
        '+', '-', '*', '/', '%', '**', '++', '--', '+=', '-=', '*=', '/=',
        '%=', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!', '&', '|',
        '^', '~', '<<', '>>', '=', '?', ':', '=>', '->', '.', ',', ';',
        '(', ')', '[', ']', '{', '}', '"', "'", '\\', '_', '$'
    }
    
    # Common vulnerability patterns to highlight
    VULNERABILITY_PATTERNS = {
        'reentrancy': [
            r'\.call\s*\{.*\}\s*\(\s*["\'].*["\']\s*\)',
            r'\.call\s*\(\s*.*\s*\)',
            r'\.delegatecall\s*\(\s*.*\s*\)',
            r'\.transfer\s*\(\s*.*\s*\)',
            r'\.send\s*\(\s*.*\s*\)'
        ],
        'access_control': [
            r'tx\.origin\s*==',
            r'msg\.sender\s*==\s*owner',
            r'onlyOwner',
            r'require\s*\(\s*msg\.sender\s*==',
        ],
        'integer_overflow': [
            r'\+\s*=',
            r'-\s*=',
            r'\*\s*=',
            r'/\s*=',
            r'\+\+',
            r'--',
            r'\*\s+\w+',
        ],
        'unchecked_calls': [
            r'\.call\s*\(',
            r'\.delegatecall\s*\(',
            r'\.staticcall\s*\(',
            r'\.send\s*\(',
        ]
    }
    
    def __init__(self, base_tokenizer: Optional[str] = None):
        """Initialize Solidity tokenizer."""
        self.base_tokenizer = None
        if base_tokenizer:
            try:
                self.base_tokenizer = AutoTokenizer.from_pretrained(base_tokenizer)
            except Exception as e:
                logger.warning(f"Could not load base tokenizer {base_tokenizer}: {e}")
        
        # Compile vulnerability patterns
        self.compiled_patterns = {}
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            self.compiled_patterns[vuln_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
    
    def tokenize(self, code: str) -> List[SolidityToken]:
        """Tokenize Solidity code with semantic annotations."""
        tokens = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_tokens = self._tokenize_line(line, line_num)
            tokens.extend(line_tokens)
        
        return tokens
    
    def _tokenize_line(self, line: str, line_num: int) -> List[SolidityToken]:
        """Tokenize a single line of code."""
        tokens = []
        
        # Remove comments but preserve structure
        line_without_comments = re.sub(r'//.*$', '', line)
        line_without_comments = re.sub(r'/\*.*?\*/', '', line_without_comments)
        
        # Token patterns (order matters!)
        patterns = [
            (r'\b0x[0-9a-fA-F]+\b', 'HEX_LITERAL'),
            (r'\b\d+\.?\d*([eE][+-]?\d+)?\b', 'NUMBER_LITERAL'),
            (r'"[^"]*"', 'STRING_LITERAL'),
            (r"'[^']*'", 'STRING_LITERAL'),
            (r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', 'IDENTIFIER'),
            (r'[+\-*/%=<>!&|^~()[\]{}.,;:]', 'OPERATOR'),
            (r'\s+', 'WHITESPACE'),
        ]
        
        pos = 0
        while pos < len(line_without_comments):
            matched = False
            
            for pattern, token_type in patterns:
                regex = re.compile(pattern)
                match = regex.match(line_without_comments, pos)
                
                if match:
                    text = match.group()
                    
                    if token_type != 'WHITESPACE':  # Skip whitespace tokens
                        token = SolidityToken(
                            text=text,
                            token_type=token_type,
                            line=line_num,
                            column=pos,
                            is_identifier=(token_type == 'IDENTIFIER'),
                            is_keyword=(text.lower() in self.KEYWORDS),
                            is_literal=(token_type.endswith('_LITERAL')),
                        )
                        
                        # Enhance token with semantic information
                        self._enhance_token(token, line_without_comments, pos)
                        tokens.append(token)
                    
                    pos = match.end()
                    matched = True
                    break
            
            if not matched:
                # Handle unrecognized character
                tokens.append(SolidityToken(
                    text=line_without_comments[pos],
                    token_type='UNKNOWN',
                    line=line_num,
                    column=pos
                ))
                pos += 1
        
        return tokens
    
    def _enhance_token(self, token: SolidityToken, line: str, pos: int):
        """Add semantic information to tokens."""
        
        # Check if identifier is a function
        if token.is_identifier:
            # Look ahead for opening parenthesis
            remaining = line[pos + len(token.text):].lstrip()
            if remaining.startswith('('):
                token.is_function = True
            
            # Check if it's a modifier
            if token.text in ['onlyOwner', 'nonReentrant', 'whenPaused']:
                token.is_modifier = True
    
    def detect_vulnerabilities(self, code: str) -> Dict[str, List[Tuple[int, str]]]:
        """Detect potential vulnerability patterns in code."""
        vulnerabilities = {}
        lines = code.split('\n')
        
        for vuln_type, patterns in self.compiled_patterns.items():
            matches = []
            
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    for match in pattern.finditer(line):
                        matches.append((line_num, match.group()))
            
            if matches:
                vulnerabilities[vuln_type] = matches
        
        return vulnerabilities
    
    def extract_functions(self, code: str) -> List[Dict]:
        """Extract function definitions and their metadata."""
        functions = []
        
        # Pattern to match function definitions
        function_pattern = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)\s*(public|private|internal|external)?\s*(view|pure|payable)?\s*(returns\s*\([^)]*\))?\s*\{',
            re.MULTILINE
        )
        
        for match in function_pattern.finditer(code):
            function_info = {
                'name': match.group(1),
                'visibility': match.group(2) or 'public',
                'state_mutability': match.group(3) or 'nonpayable',
                'returns': match.group(4) or '',
                'start_pos': match.start(),
                'line': code[:match.start()].count('\n') + 1
            }
            functions.append(function_info)
        
        return functions
    
    def extract_contracts(self, code: str) -> List[Dict]:
        """Extract contract definitions."""
        contracts = []
        
        # Pattern to match contract definitions
        contract_pattern = re.compile(
            r'(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{',
            re.MULTILINE
        )
        
        for match in contract_pattern.finditer(code):
            contract_info = {
                'type': match.group(1),
                'name': match.group(2),
                'inheritance': match.group(3).strip() if match.group(3) else None,
                'start_pos': match.start(),
                'line': code[:match.start()].count('\n') + 1
            }
            contracts.append(contract_info)
        
        return contracts
    
    def encode_for_model(self, code: str, max_length: int = 512) -> Dict:
        """Encode Solidity code for model input."""
        if self.base_tokenizer:
            # Use base tokenizer for model compatibility
            encoding = self.base_tokenizer(
                code,
                truncation=True,
                padding='max_length',
                max_length=max_length,
                return_tensors='pt'
            )
            return encoding
        else:
            # Fallback to simple word-based encoding
            tokens = self.tokenize(code)
            token_texts = [token.text for token in tokens if token.token_type != 'WHITESPACE']
            
            return {
                'tokens': token_texts[:max_length],
                'length': min(len(token_texts), max_length)
            }
    
    def add_vulnerability_markers(self, code: str) -> str:
        """Add special markers around potential vulnerability patterns."""
        marked_code = code
        
        # Add markers for different vulnerability types
        markers = {
            'reentrancy': ('<REENTRANCY>', '</REENTRANCY>'),
            'access_control': ('<ACCESS>', '</ACCESS>'),
            'integer_overflow': ('<OVERFLOW>', '</OVERFLOW>'),
            'unchecked_calls': ('<UNCHECKED>', '</UNCHECKED>')
        }
        
        for vuln_type, patterns in self.compiled_patterns.items():
            start_marker, end_marker = markers.get(vuln_type, ('', ''))
            
            for pattern in patterns:
                marked_code = pattern.sub(
                    lambda m: f"{start_marker}{m.group()}{end_marker}",
                    marked_code
                )
        
        return marked_code


class SolidityDatasetTokenizer:
    """Tokenizer specifically designed for dataset creation and training."""
    
    def __init__(self, model_name: str = "microsoft/CodeBERT-base"):
        self.solidity_tokenizer = SolidityTokenizer()
        self.model_tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        # Set up padding token (required for batch processing)
        if self.model_tokenizer.pad_token is None:
            self.model_tokenizer.pad_token = self.model_tokenizer.eos_token
        
        # Add special tokens for vulnerabilities
        special_tokens = [
            '<VULNERABLE>', '</VULNERABLE>',
            '<REENTRANCY>', '</REENTRANCY>',
            '<ACCESS>', '</ACCESS>',
            '<OVERFLOW>', '</OVERFLOW>',
            '<UNCHECKED>', '</UNCHECKED>',
            '<FIXED>', '</FIXED>'
        ]
        
        self.model_tokenizer.add_special_tokens({
            'additional_special_tokens': special_tokens
        })
    
    def prepare_training_data(
        self,
        vulnerable_code: str,
        fixed_code: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        max_length: int = 512
    ) -> Dict:
        """Prepare code for training with vulnerability markers."""
        
        # Add vulnerability markers
        if vulnerability_type:
            marked_vulnerable = self.solidity_tokenizer.add_vulnerability_markers(vulnerable_code)
            marked_vulnerable = f"<VULNERABLE>{marked_vulnerable}</VULNERABLE>"
        else:
            marked_vulnerable = vulnerable_code
        
        # Prepare inputs
        inputs = self.model_tokenizer(
            marked_vulnerable,
            truncation=True,
            padding='max_length',
            max_length=max_length,
            return_tensors='pt'
        )
        
        result = {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask'],
            'vulnerable_code': vulnerable_code
        }
        
        # Add fixed code as target if available
        if fixed_code:
            fixed_inputs = self.model_tokenizer(
                f"<FIXED>{fixed_code}</FIXED>",
                truncation=True,
                padding='max_length',
                max_length=max_length,
                return_tensors='pt'
            )
            result['fixed_input_ids'] = fixed_inputs['input_ids']
            result['fixed_code'] = fixed_code
        
        return result
    
    def get_vocab_size(self) -> int:
        """Get the vocabulary size including special tokens."""
        return len(self.model_tokenizer)
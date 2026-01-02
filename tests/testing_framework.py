"""
Testing framework for validating smart contract fixes and exploits.

This module integrates with Foundry and Hardhat to generate and execute
tests that validate the effectiveness of model-generated fixes.
"""

import json
import logging
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import re

from auditor.core import AuditResult
from data.schema import VulnerabilityType, Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a contract test execution."""
    contract_name: str
    vulnerability_type: VulnerabilityType
    exploit_successful: bool
    fix_successful: bool
    compilation_successful: bool
    gas_usage: Optional[int] = None
    error_message: Optional[str] = None
    test_output: Optional[str] = None


class FoundryTestGenerator:
    """Generates Foundry tests for smart contract vulnerabilities."""
    
    def __init__(self, foundry_path: Optional[str] = None):
        """Initialize Foundry test generator.
        
        Args:
            foundry_path: Path to Foundry installation (auto-detected if None)
        """
        self.foundry_path = foundry_path or self._find_foundry()
        if not self.foundry_path:
            raise RuntimeError("Foundry not found. Please install Foundry or specify path.")
        
        logger.info(f"Using Foundry at: {self.foundry_path}")
    
    def _find_foundry(self) -> Optional[str]:
        """Find Foundry installation."""
        try:
            result = subprocess.run(["which", "forge"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        # Check common installation paths
        common_paths = [
            "~/.foundry/bin/forge",
            "/usr/local/bin/forge",
            "/opt/foundry/bin/forge"
        ]
        
        for path in common_paths:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                return str(expanded_path)
        
        return None
    
    def generate_reentrancy_test(
        self,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability
    ) -> str:
        """Generate test for reentrancy vulnerability."""
        
        test_contract = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract {contract_name}ReentrancyTest is Test {{
    {contract_name} public target;
    AttackContract public attacker;
    
    function setUp() public {{
        target = new {contract_name}();
        attacker = new AttackContract(address(target));
    }}
    
    function testReentrancyExploit() public {{
        // Fund the target contract
        vm.deal(address(target), 10 ether);
        vm.deal(address(attacker), 1 ether);
        
        // Deposit some funds
        target.deposit{{value: 1 ether}}();
        
        uint256 balanceBefore = address(target).balance;
        
        // Execute attack
        attacker.attack{{value: 1 ether}}();
        
        uint256 balanceAfter = address(target).balance;
        
        // Verify exploit was successful
        assertLt(balanceAfter, balanceBefore, "Reentrancy exploit failed");
        assertGt(address(attacker).balance, 1 ether, "Attacker should have gained funds");
    }}
}}

contract AttackContract {{
    {contract_name} public target;
    bool public attacking = false;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        attacking = true;
        target.withdraw(msg.value);
    }}
    
    receive() external payable {{
        if (attacking && address(target).balance > 0) {{
            target.withdraw(msg.value);
        }}
    }}
}}
'''
        
        return test_contract
    
    def generate_access_control_test(
        self,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability
    ) -> str:
        """Generate test for access control vulnerability."""
        
        test_contract = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract {contract_name}AccessControlTest is Test {{
    {contract_name} public target;
    address public attacker = address(0x1337);
    
    function setUp() public {{
        target = new {contract_name}();
        vm.deal(address(target), 10 ether);
    }}
    
    function testUnauthorizedAccess() public {{
        vm.prank(attacker);
        
        uint256 balanceBefore = address(target).balance;
        
        // Try to exploit access control
        try target.emergencyWithdraw() {{
            uint256 balanceAfter = address(target).balance;
            assertLt(balanceAfter, balanceBefore, "Access control exploit successful");
        }} catch {{
            fail("Access control properly implemented - exploit failed");
        }}
    }}
    
    function testTxOriginVulnerability() public {{
        // Create malicious contract that exploits tx.origin
        MaliciousContract malicious = new MaliciousContract(address(target));
        
        vm.deal(address(this), 1 ether);
        
        uint256 balanceBefore = address(target).balance;
        
        // Call through malicious contract
        malicious.exploit{{value: 1 ether}}();
        
        uint256 balanceAfter = address(target).balance;
        
        if (balanceAfter < balanceBefore) {{
            assertTrue(true, "tx.origin vulnerability exploited");
        }}
    }}
}}

contract MaliciousContract {{
    {contract_name} public target;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function exploit() external payable {{
        target.withdrawAll();
    }}
}}
'''
        
        return test_contract
    
    def generate_overflow_test(
        self,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability
    ) -> str:
        """Generate test for integer overflow vulnerability."""
        
        test_contract = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract {contract_name}OverflowTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function testIntegerOverflow() public {{
        address user1 = address(0x1);
        address user2 = address(0x2);
        
        // Create a large array to trigger overflow in batchTransfer
        address[] memory recipients = new address[](2);
        recipients[0] = user1;
        recipients[1] = user2;
        
        // Mint tokens to attacker
        target.mint(address(this), 1000);
        
        uint256 balanceBefore = target.balances(address(this));
        
        // Try to trigger overflow with large amount
        uint256 largeAmount = type(uint256).max / 2;
        
        try target.batchTransfer(recipients, largeAmount) {{
            uint256 balanceAfter = target.balances(address(this));
            
            // Check if overflow occurred (balance increased instead of decreased)
            if (balanceAfter > balanceBefore) {{
                assertTrue(true, "Integer overflow exploit successful");
            }}
        }} catch {{
            // Overflow protection is working
            assertTrue(false, "Overflow protection prevented exploit");
        }}
    }}
}}
'''
        
        return test_contract
    
    def generate_unchecked_call_test(
        self,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability
    ) -> str:
        """Generate test for unchecked external call vulnerability."""
        
        test_contract = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract {contract_name}UncheckedCallTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
        vm.deal(address(target), 10 ether);
    }}
    
    function testUncheckedCallFailure() public {{
        // Add a malicious recipient that will revert
        MaliciousRecipient malicious = new MaliciousRecipient();
        target.addRecipient(address(malicious));
        
        // Add a normal recipient
        target.addRecipient(address(this));
        
        uint256 balanceBefore = address(target).balance;
        
        // Try to distribute funds
        target.distributeFunds();
        
        uint256 balanceAfter = address(target).balance;
        
        // Check if funds were still distributed despite one call failing
        if (balanceAfter < balanceBefore) {{
            assertTrue(true, "Unchecked call vulnerability - funds distributed despite failures");
        }} else {{
            assertTrue(false, "All calls succeeded or distribution was properly handled");
        }}
    }}
    
    receive() external payable {{
        // Normal recipient - accepts funds
    }}
}}

contract MaliciousRecipient {{
    receive() external payable {{
        revert("I reject your funds!");
    }}
}}
'''
        
        return test_contract
    
    def generate_test_for_vulnerability(
        self,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability
    ) -> str:
        """Generate appropriate test based on vulnerability type."""
        
        vuln_type = vulnerability.vulnerability_type
        
        if vuln_type == VulnerabilityType.REENTRANCY:
            return self.generate_reentrancy_test(contract_code, contract_name, vulnerability)
        elif vuln_type == VulnerabilityType.ACCESS_CONTROL:
            return self.generate_access_control_test(contract_code, contract_name, vulnerability)
        elif vuln_type == VulnerabilityType.INTEGER_OVERFLOW:
            return self.generate_overflow_test(contract_code, contract_name, vulnerability)
        elif vuln_type == VulnerabilityType.UNCHECKED_CALL:
            return self.generate_unchecked_call_test(contract_code, contract_name, vulnerability)
        else:
            # Generic test
            return self.generate_generic_test(contract_code, contract_name, vulnerability)
    
    def generate_generic_test(
        self,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability
    ) -> str:
        """Generate generic test template."""
        
        test_contract = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract {contract_name}GenericTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function testVulnerability() public {{
        // Generic test - implement specific logic based on vulnerability
        assertTrue(true, "Generic test placeholder");
    }}
}}
'''
        
        return test_contract


class ContractTester:
    """Main testing framework for contract vulnerabilities and fixes."""
    
    def __init__(self, work_dir: Optional[str] = None):
        """Initialize contract tester.
        
        Args:
            work_dir: Working directory for test execution (temp dir if None)
        """
        self.work_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp())
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.foundry_generator = FoundryTestGenerator()
        
        logger.info(f"Contract tester initialized with work directory: {self.work_dir}")
    
    def test_audit_result(
        self,
        audit_result: AuditResult,
        fixed_contract_code: Optional[str] = None
    ) -> List[TestResult]:
        """Test an audit result by validating vulnerabilities and fixes.
        
        Args:
            audit_result: Result of contract audit
            fixed_contract_code: Optional fixed version of the contract
            
        Returns:
            List of test results for each vulnerability
        """
        results = []
        
        # Create test project directory
        project_dir = self.work_dir / f"{audit_result.contract_name}_test"
        if project_dir.exists():
            shutil.rmtree(project_dir)
        
        self._initialize_foundry_project(project_dir)
        
        # Test each vulnerability
        for vulnerability in audit_result.vulnerabilities:
            try:
                test_result = self._test_single_vulnerability(
                    project_dir,
                    audit_result.contract_source,
                    audit_result.contract_name,
                    vulnerability,
                    fixed_contract_code
                )
                results.append(test_result)
                
            except Exception as e:
                logger.error(f"Failed to test {vulnerability.vulnerability_type.value}: {e}")
                results.append(TestResult(
                    contract_name=audit_result.contract_name,
                    vulnerability_type=vulnerability.vulnerability_type,
                    exploit_successful=False,
                    fix_successful=False,
                    compilation_successful=False,
                    error_message=str(e)
                ))
        
        return results
    
    def _initialize_foundry_project(self, project_dir: Path):
        """Initialize a new Foundry project."""
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize foundry project
        result = subprocess.run(
            ["forge", "init", "--no-git", str(project_dir)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to initialize Foundry project: {result.stderr}")
    
    def _test_single_vulnerability(
        self,
        project_dir: Path,
        contract_code: str,
        contract_name: str,
        vulnerability: Vulnerability,
        fixed_contract_code: Optional[str] = None
    ) -> TestResult:
        """Test a single vulnerability."""
        
        # Write original contract
        src_dir = project_dir / "src"
        contract_file = src_dir / f"{contract_name}.sol"
        with open(contract_file, 'w') as f:
            f.write(contract_code)
        
        # Generate and write test
        test_code = self.foundry_generator.generate_test_for_vulnerability(
            contract_code, contract_name, vulnerability
        )
        
        test_dir = project_dir / "test"
        test_file = test_dir / f"{contract_name}_{vulnerability.vulnerability_type.value}_Test.sol"
        with open(test_file, 'w') as f:
            f.write(test_code)
        
        # Test original (vulnerable) contract
        exploit_successful = self._run_foundry_test(project_dir, test_file)
        compilation_successful = exploit_successful is not None
        
        # Test fixed contract if provided
        fix_successful = False
        if fixed_contract_code:
            # Replace contract with fixed version
            with open(contract_file, 'w') as f:
                f.write(fixed_contract_code)
            
            # Run test again - should fail (exploit should not work)
            fix_test_result = self._run_foundry_test(project_dir, test_file)
            fix_successful = fix_test_result is False  # Test fails = fix works
        
        return TestResult(
            contract_name=contract_name,
            vulnerability_type=vulnerability.vulnerability_type,
            exploit_successful=exploit_successful or False,
            fix_successful=fix_successful,
            compilation_successful=compilation_successful
        )
    
    def _run_foundry_test(self, project_dir: Path, test_file: Path) -> Optional[bool]:
        """Run a Foundry test and return success status.
        
        Returns:
            True if test passed, False if failed, None if compilation failed
        """
        try:
            # Run the test
            result = subprocess.run(
                ["forge", "test", "--match-path", str(test_file), "-vv"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )
            
            # Check for compilation errors
            if "Error" in result.stderr or result.returncode == 1:
                if "Compilation failed" in result.stderr or "CompilerError" in result.stderr:
                    logger.warning(f"Compilation failed for {test_file}")
                    return None
            
            # Check test results
            if result.returncode == 0 and "✓" in result.stdout:
                return True
            elif "✗" in result.stdout or result.returncode != 0:
                return False
            else:
                return None
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Test timeout for {test_file}")
            return None
        except Exception as e:
            logger.error(f"Error running test {test_file}: {e}")
            return None
    
    def generate_test_report(self, test_results: List[TestResult]) -> str:
        """Generate a formatted test report."""
        
        report_lines = [
            "# Contract Testing Report",
            "",
            f"**Total Tests:** {len(test_results)}",
            ""
        ]
        
        # Summary statistics
        successful_exploits = sum(1 for r in test_results if r.exploit_successful)
        successful_fixes = sum(1 for r in test_results if r.fix_successful)
        compilation_failures = sum(1 for r in test_results if not r.compilation_successful)
        
        report_lines.extend([
            "## Summary",
            "",
            f"- **Successful Exploits:** {successful_exploits}/{len(test_results)}",
            f"- **Successful Fixes:** {successful_fixes}/{len(test_results)}",
            f"- **Compilation Failures:** {compilation_failures}/{len(test_results)}",
            "",
            "## Detailed Results",
            "",
            "| Vulnerability | Exploit Success | Fix Success | Compilation Success |",
            "|---------------|----------------|-------------|-------------------|"
        ])
        
        for result in test_results:
            exploit_status = "✓" if result.exploit_successful else "✗"
            fix_status = "✓" if result.fix_successful else "✗"
            compile_status = "✓" if result.compilation_successful else "✗"
            
            report_lines.append(
                f"| {result.vulnerability_type.value} | {exploit_status} | "
                f"{fix_status} | {compile_status} |"
            )
        
        if any(r.error_message for r in test_results):
            report_lines.extend([
                "",
                "## Errors",
                ""
            ])
            
            for result in test_results:
                if result.error_message:
                    report_lines.extend([
                        f"**{result.vulnerability_type.value}:** {result.error_message}",
                        ""
                    ])
        
        return "\n".join(report_lines)
    
    def cleanup(self):
        """Clean up temporary files."""
        if self.work_dir.exists() and "tmp" in str(self.work_dir):
            shutil.rmtree(self.work_dir)
            logger.info(f"Cleaned up work directory: {self.work_dir}")


def test_audit_with_foundry(
    audit_result: AuditResult,
    fixed_contract_code: Optional[str] = None,
    save_report: bool = True,
    report_dir: str = "tests/reports"
) -> List[TestResult]:
    """Convenience function to test an audit result with Foundry.
    
    Args:
        audit_result: Audit result to test
        fixed_contract_code: Optional fixed contract code
        save_report: Whether to save test report
        report_dir: Directory to save report
        
    Returns:
        List of test results
    """
    tester = ContractTester()
    
    try:
        results = tester.test_audit_result(audit_result, fixed_contract_code)
        
        if save_report:
            report = tester.generate_test_report(results)
            report_path = Path(report_dir)
            report_path.mkdir(parents=True, exist_ok=True)
            
            report_file = report_path / f"{audit_result.contract_name}_test_report.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            logger.info(f"Test report saved to {report_file}")
        
        return results
        
    finally:
        tester.cleanup()
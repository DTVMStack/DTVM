#!/usr/bin/env python3
"""
EVM Assembly Test Runner
Usage: ./tools/run_evm_tests.py -r ./build/dtvm -m multipass --format evm
"""

import os
import sys
import time
import argparse
import subprocess
import yaml
from typing import Dict, Any, List, Tuple

class Statistics:
    """Statistics class for tracking test results"""
    def __init__(self):
        self.succ = 0
        self.fail = 0
        self.ignore = 0
        self.total = 0

    def addSucc(self, count: int = 1):
        self.succ += count

    def addFail(self, count: int = 1):
        self.fail += count

    def addIgnore(self, count: int = 1):
        self.ignore += count

    def getSummary(self) -> Dict[str, int]:
        return {
            'total': self.succ + self.fail + self.ignore,
            'succ': self.succ,
            'fail': self.fail,
            'ignore': self.ignore
        }

class TestCase:
    """Test case class"""
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.name = os.path.basename(file_path)
        self.expected_file = file_path.replace('.evm.hex', '.expected')
        self.has_expected = os.path.exists(self.expected_file)
        self.is_ignored = False

class TestRunner:
    """Main test runner class"""

    IGNORE_CASES = {
    }

    def __init__(self, args):
        self.args = args
        self.runtime_path = self.validateRuntime()
        self.test_dir = self.validateTestDir()
        self.statistics = Statistics()
        self.test_cases: List[TestCase] = []
        self.ignored_cases: List[TestCase] = []
        self.failed_cases: List[TestCase] = []
        self.start_time = None

    def validateRuntime(self) -> str:
        """Validate runtime path"""
        runtime_path = self.args.runtime
        if not os.path.isfile(runtime_path):
            runtime_path = f"build/{self.args.runtime}"
            if not os.path.isfile(runtime_path):
                print(f"Error: Runtime executable not found: {self.args.runtime}")
                sys.exit(1)

        if not os.access(runtime_path, os.X_OK):
            print(f"Error: Runtime executable not executable: {runtime_path}")
            sys.exit(1)

        return runtime_path

    def validateTestDir(self) -> str:
        """Validate test directory"""
        test_dir = self.args.test_dir
        if not os.path.isdir(test_dir):
            print(f"Error: Test directory not found: {test_dir}")
            sys.exit(1)
        return test_dir

    def parseYamlOutput(self, yaml_str: str) -> Dict[str, Any]:
        """Parse YAML output"""
        try:
            return yaml.safe_load(yaml_str) or {}
        except yaml.YAMLError as e:
            print(f"Error parsing YAML: {e}")
            return {}

    def checkResults(self, actual: Dict[str, Any], expected: Dict[str, Any]) -> Tuple[bool, str]:
        """Check actual and expected results"""
        # TODO: check stack, memory
        important_fields = ['status', 'error_code', 'return']

        for field in important_fields:
            actual_val = actual.get(field)
            expected_val = expected.get(field)
            if actual_val != expected_val:
                return False, f"Field '{field}' mismatch: expected {expected_val}, got {actual_val}"

        return True, ""

    def getSuiteCases(self) -> List[TestCase]:
        """Discover test cases"""
        test_cases = []

        # Handle a single test file
        if self.args.single_case:
            file_path = self.args.single_case
            if not os.path.isfile(file_path):
                print(f"Error: Single test file not found: {file_path}")
                sys.exit(1)
            if not file_path.endswith('.evm.hex'):
                print(f"Error: Single test file must end with .evm.hex: {file_path}")
                sys.exit(1)

            test_case = TestCase(file_path)
            # When using --single-case, always execute regardless of IGNORE_CASES
            test_case.is_ignored = False
            self.test_cases.append(test_case)
            return self.test_cases

        for file in sorted(os.listdir(self.test_dir)):
            if not file.endswith('.evm.hex'):
                continue

            if self.args.filter and self.args.filter not in file:
                continue

            test_case = TestCase(os.path.join(self.test_dir, file))
            # Only ignore cases in multipass mode
            test_case.is_ignored = self.args.mode == "multipass" and file in self.IGNORE_CASES

            if test_case.is_ignored:
                self.statistics.addIgnore()
                self.ignored_cases.append(test_case)
                if self.args.verbose:
                    print(f"IGNORE {file:<40} (in ignore list)")
                continue

            self.test_cases.append(test_case)

        return self.test_cases

    def buildCommand(self, test_case: TestCase) -> List[str]:
        """Build test command"""
        cmd = [
            self.runtime_path,
            "--format", self.args.format,
            "-m", self.args.mode
        ]

        if self.args.enable_multipass_lazy:
            cmd.append("--enable-multipass-lazy")

        if self.args.num_multipass_threads is not None:
            cmd.extend(["--num-multipass-threads", str(self.args.num_multipass_threads)])

        if self.args.disable_multipass_multithread:
            cmd.append("--disable-multipass-multithread")

        if self.args.gas_limit:
            cmd.extend(["--gas-limit", str(self.args.gas_limit)])

        if self.args.enable_evm_gas:
            cmd.append("--enable-evm-gas")

        if self.args.zen_options:
            cmd.extend(self.args.zen_options.split())

        cmd.append(test_case.file_path)
        return cmd

    def parseTestOutput(self, stdout: str, returncode: int) -> Dict[str, Any]:
        """Parse test output"""
        # Map return code to EVM status based on EVMC specification, same as `evmc::to_string(evmc_status_code)`
        status_map = {
            0: "success",                    # EVMC_SUCCESS
            1: "failure",                    # EVMC_FAILURE
            2: "revert",                     # EVMC_REVERT
            3: "out of gas",                 # EVMC_OUT_OF_GAS
            4: "invalid instruction",        # EVMC_INVALID_INSTRUCTION
            5: "undefined instruction",      # EVMC_UNDEFINED_INSTRUCTION
            6: "stack overflow",             # EVMC_STACK_OVERFLOW
            7: "stack underflow",            # EVMC_STACK_UNDERFLOW
            8: "bad jump destination",       # EVMC_BAD_JUMP_DESTINATION
            9: "invalid memory access",      # EVMC_INVALID_MEMORY_ACCESS
            10: "call depth exceeded",       # EVMC_CALL_DEPTH_EXCEEDED
            11: "static mode violation",     # EVMC_STATIC_MODE_VIOLATION
            12: "precompile failure",        # EVMC_PRECOMPILE_FAILURE
            13: "contract validation_failure", # EVMC_CONTRACT_VALIDATION_FAILURE
            14: "argument out of range",     # EVMC_ARGUMENT_OUT_OF_RANGE
            15: "wasm unreachable instruction", # EVMC_WASM_UNREACHABLE_INSTRUCTION
            16: "wasm trap",                 # EVMC_WASM_TRAP
            17: "insufficient balance",     # EVMC_INSUFFICIENT_BALANCE
            -1: "internal error",            # EVMC_INTERNAL_ERROR
            -2: "rejected",                  # EVMC_REJECTED
            -3: "out of memory"              # EVMC_OUT_OF_MEMORY
        }

        return_value = ""
        if "output: 0x" in stdout:
            start = stdout.find("output: 0x") + 10
            hex_value = stdout[start:].split("\n", 1)[0].strip()
            return_value = hex_value[2:] if hex_value.startswith("0x") else hex_value

        return {
            "status": status_map.get(returncode, "failure"),
            "error_code": returncode,
            "stack": [],
            "memory": [],
            "return": return_value
        }

    def runOneCase(self, test_case: TestCase) -> bool:
        """Run single test case"""
        if not test_case.has_expected:
            self.statistics.addIgnore()
            self.ignored_cases.append(test_case)
            if self.args.verbose:
                print(f"IGNORE {test_case.name:<40} (no .expected)", file=sys.stderr)
            return True

        cmd = self.buildCommand(test_case)

        start_time = time.time()
        try:
            if self.args.dmirlog:
                print(f"\n{'='*80}")
                print(f"TEST CASE: {test_case.name}")
                print(f"FILE: {test_case.file_path}")
                print(f"{'='*80}")

                # Run the command and capture output
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.stdout:
                    print(result.stdout, end="")
                if result.stderr:
                    print(result.stderr, end="")

                elapsed = (time.time() - start_time) * 1000

                with open(test_case.expected_file, 'r', encoding='utf-8') as f:
                    expected_data = self.parseYamlOutput(f.read())
                expected_returncode = expected_data.get('error_code', 0)

                # Print result
                print(f"\n{'='*80}")
                if result.returncode == expected_returncode:
                    self.statistics.addSucc()
                    print(f"✅ PASSED: {test_case.name} ({elapsed:.1f}ms)")
                else:
                    self.statistics.addFail()
                    print(f"❌ FAILED: {test_case.name} ({elapsed:.1f}ms) - return code mismatch: expected {expected_returncode}, got {result.returncode}")
                    self.failed_cases.append(test_case)
                print(f"{'='*80}\n")
                return result.returncode == expected_returncode
            else:
                # capture output and parse
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                elapsed = (time.time() - start_time) * 1000

                # Parse expected results
                with open(test_case.expected_file, 'r', encoding='utf-8') as f:
                    expected_data = self.parseYamlOutput(f.read())

                # Parse actual results
                actual_data = self.parseTestOutput(result.stdout, result.returncode)

                # Compare results
                is_match, error_msg = self.checkResults(actual_data, expected_data)

                expected_returncode = expected_data.get('error_code', 0)
                returncode_match = result.returncode == expected_returncode
                if returncode_match and is_match:
                    self.statistics.addSucc()
                    print(f"PASSED {test_case.name:<40} ({elapsed:.1f}ms)")
                    return True
                else:
                    self.statistics.addFail()
                    self.failed_cases.append(test_case)
                    print(f"FAILED {test_case.name:<40} ({elapsed:.1f}ms)")

                    if self.args.verbose or not is_match or not returncode_match:
                        if result.stderr:
                            print(f"    stderr: {result.stderr.strip()}")
                        if not returncode_match:
                            print(f"    return code mismatch: expected {expected_returncode}, got {result.returncode}")
                        if not is_match:
                            print(f"    {error_msg}")
                        if self.args.verbose:
                            print(f"    expected: {expected_data}")
                            print(f"    actual: {actual_data}")
                    return False

        except subprocess.TimeoutExpired:
            self.statistics.addFail()
            print(f"TIMEOUT {test_case.name:<40}")
            self.failed_cases.append(test_case)
            return False
        except Exception as e:
            self.statistics.addFail()
            print(f"ERROR {test_case.name:<40}: {e}")
            self.failed_cases.append(test_case)
            return False

    def printHeader(self):
        """Print test header"""
        print("=" * 70)
        print("EVM Assembly Test Runner")
        print("=" * 70)
        print(f"Runtime: {self.runtime_path}")
        print(f"Mode: {self.args.mode}")
        print(f"Test directory: {self.test_dir}")
        print(f"Test files: {len(self.test_cases)}")
        if self.args.zen_options:
            print(f"Extra options: {self.args.zen_options}")
        if self.args.enable_multipass_lazy:
            print("Multipass lazy: enabled")
        if self.args.num_multipass_threads is not None:
            print(f"Multipass threads: {self.args.num_multipass_threads}")
        if self.args.disable_multipass_multithread:
            print("Multipass multithread: disabled")
        if self.args.enable_evm_gas:
            print("EVM gas metering: enabled")
        if self.IGNORE_CASES:
            print(f"Ignored tests: {len(self.IGNORE_CASES)}")
        print()

    def printSummary(self):
        #print all skipped test cases
        if self.ignored_cases:
            print()
            print("=" * 70)
            print("SKIPPED TEST CASES:")
            print("=" * 70)
            for test_case in self.ignored_cases:
                print(test_case.file_path)
            print("=" * 70)

        # Print all failed test cases
        if self.failed_cases:
            print()
            print("=" * 70)
            print("FAILED TEST CASES:")
            print("=" * 70)
            for test_case in self.failed_cases:
                print(test_case.file_path)
            print("=" * 70)

        # No need to print all passed test cases

        """Print test summary"""
        summary = self.statistics.getSummary()
        print()
        print("=" * 70)
        print("Test Summary:")
        print(f"  Total:   {summary['total']}")
        print(f"  Passed:  {summary['succ']}")
        print(f"  Skipped: {summary['ignore']}")
        print(f"  Failed:  {summary['fail']}")

        elapsed = time.time() - self.start_time
        print(f"  Time:    {elapsed:.3f}s")
        print("=" * 70)

    def runAllSuites(self) -> int:
        """Run all tests"""
        self.start_time = time.time()

        # Discover test cases
        self.getSuiteCases()
        self.statistics.total = len(self.test_cases)

        if not self.test_cases:
            print(f"No test files found in {self.test_dir}")
            return 0

        self.printHeader()

        # Run tests
        failed_count = 0
        for test_case in self.test_cases:
            if not self.runOneCase(test_case):
                failed_count += 1

        self.printSummary()

        return 0 if failed_count == 0 else 1

def main():
    parser = argparse.ArgumentParser(description='EVM Assembly Test Runner')
    parser.add_argument("-r", "--run", dest="runtime", default="build/dtvm",
                        help="Runtime executable path (default: build/dtvm)")
    parser.add_argument("-m", "--mode", dest="mode", default="multipass",
                        choices=["multipass", "singlepass", "interpreter"],
                        help="Execution mode (default: multipass)")
    parser.add_argument("--format", dest="format", default="wasm",
                        help="Format parameter (default: wasm)")
    parser.add_argument("--zen-options", dest="zen_options", default="",
                        help="Additional options for dtvm")
    parser.add_argument("-t", "--test-dir", dest="test_dir", default="tests/evm_asm",
                        help="Test directory (default: tests/evm_asm)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--filter", dest="filter", default="",
                        help="Filter test files by pattern")
    parser.add_argument("--dmirlog", action="store_true",
                        help="Show detailed MIR compilation logs")
    parser.add_argument("--enable-multipass-lazy", action="store_true",
                        help="Enable multipass lazy compilation")
    parser.add_argument("--num-multipass-threads", type=int, default=None,
                        help="Number of multipass threads (default: system default)")
    parser.add_argument("--disable-multipass-multithread", action="store_true",
                        help="Disable multipass multithreading")
    parser.add_argument("--gas-limit", type=lambda x: int(x, 0), default=0xFFFFFFFFFFFF,
                        help="Gas limit for EVM execution (default: 0xFFFFFFFFFFFF)")
    parser.add_argument("--single-case", dest="single_case", default=None,
                    help="Path to a single test case file (e.g., tests/evm_asm/add_simple.evm.hex)")
    parser.add_argument("--enable-evm-gas", action="store_true",
                    help="Enable EVM gas metering")

    args = parser.parse_args()

    runner = TestRunner(args)
    return runner.runAllSuites()

if __name__ == '__main__':
    sys.exit(main())

import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, simpledialog
import os
import sys
import time
import threading
import struct
import re
import json
import tempfile
import socket
import random
import string
from pathlib import Path
from datetime import datetime
import binascii
import signal
import psutil
import math
import hashlib
import base64
from collections import defaultdict
import itertools

class PatternGenerator:
    @staticmethod
    def create(length):
        pattern = ""
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        chars += "abcdefghijklmnopqrstuvwxyz0123456789"
        a = b = c = 0
        while len(pattern) < length:
            pattern += chars[a] + chars[b] + chars[c]
            c += 1
            if c >= len(chars):
                c = 0
                b += 1
            if b >= len(chars):
                b = 0
                a += 1
            if a >= len(chars):
                a = 0
        return pattern[:length]

    @staticmethod
    def offset(value, max_length=10000):
        if isinstance(value, int):
            if value <= 0xffffffff:
                bytes_val = struct.pack('<I', value)
            else:
                bytes_val = struct.pack('<Q', value)
            search = bytes_val.decode('latin-1')
        elif isinstance(value, str):
            if value.startswith('0x'):
                hex_str = value[2:]
                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str
                try:
                    search = bytes.fromhex(hex_str).decode('latin-1')
                except:
                    return -1
            else:
                search = value
        else:
            return -1
        pattern = PatternGenerator.create(max_length)
        if search in pattern:
            return pattern.index(search)
        if search[::-1] in pattern:
            return pattern.index(search[::-1])
        return -1

class BinaryRunner:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.process = None

    def run_with_input(self, input_data, timeout=3):
        try:
            self.process = subprocess.Popen(
                [self.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                shell=False
            )
            stdout, stderr = self.process.communicate(
                input=input_data.encode() if isinstance(input_data, str) else input_data,
                timeout=timeout
            )
            return {
                'success': True,
                'stdout': stdout.decode('latin-1', errors='ignore'),
                'stderr': stderr.decode('latin-1', errors='ignore'),
                'returncode': self.process.returncode,
                'crashed': self.process.returncode < 0
            }
        except subprocess.TimeoutExpired:
            if self.process:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except:
                    pass
            return {'success': False, 'timeout': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            self.kill()

    def run_interactive(self, inputs, timeout=5):
        try:
            self.process = subprocess.Popen(
                [self.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                shell=False
            )
            output = ""
            for inp in inputs:
                if isinstance(inp, str):
                    inp = inp.encode()
                self.process.stdin.write(inp + b'\n')
                self.process.stdin.flush()
                time.sleep(0.05)
            stdout, stderr = self.process.communicate(timeout=timeout)
            output = stdout.decode('latin-1', errors='ignore') + stderr.decode('latin-1', errors='ignore')
            return {
                'success': True,
                'output': output,
                'returncode': self.process.returncode,
                'crashed': self.process.returncode < 0
            }
        except subprocess.TimeoutExpired:
            if self.process:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except:
                    pass
            return {'success': False, 'timeout': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            self.kill()

    def kill(self):
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            except:
                pass
            self.process = None

class AdvancedBinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.info = {}
        self.control_flow = []
        self.disassembly = ""
        self.stripped = False

    def analyze(self):
        self.info = {}
        result = self.run_command(['file', self.binary])
        if result['success']:
            self.info['file_info'] = result['stdout'].strip()
            if 'stripped' in result['stdout'].lower():
                self.stripped = True
        self.info['architecture'] = self.get_architecture()
        self.info['protections'] = self.get_protections()
        self.info['functions'] = self.get_functions()
        self.info['imports'] = self.get_imports()
        self.info['sections'] = self.get_sections()
        self.info['entry_point'] = self.get_entry_point()
        self.disassemble()
        self.analyze_control_flow()
        return self.info

    def run_command(self, cmd, timeout=10):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True
            )
            return {
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_architecture(self):
        result = self.run_command(['readelf', '-h', self.binary])
        if result['success']:
            if 'Class:.*ELF64' in result['stdout']:
                return {'arch': 'x64', 'bits': 64}
            elif 'Class:.*ELF32' in result['stdout']:
                return {'arch': 'x86', 'bits': 32}
            elif 'Machine:.*ARM' in result['stdout']:
                return {'arch': 'ARM', 'bits': 32}
            elif 'Machine:.*AArch64' in result['stdout']:
                return {'arch': 'ARM64', 'bits': 64}
            elif 'Machine:.*MIPS' in result['stdout']:
                return {'arch': 'MIPS', 'bits': 32}
        return {'arch': 'unknown', 'bits': 0}

    def get_protections(self):
        protections = {
            'NX': 'Unknown',
            'PIE': 'Unknown',
            'Canary': 'Unknown',
            'RELRO': 'Unknown'
        }
        try:
            checksec_output = subprocess.check_output(
                ['bash', '-c', f'checksec --file={self.binary} 2>/dev/null || echo "No checksec"'],
                text=True
            )
            if 'No checksec' not in checksec_output:
                if 'NX enabled' in checksec_output:
                    protections['NX'] = 'YES'
                elif 'NX disabled' in checksec_output:
                    protections['NX'] = 'NO'
                
                if 'PIE enabled' in checksec_output:
                    protections['PIE'] = 'YES'
                elif 'No PIE' in checksec_output:
                    protections['PIE'] = 'NO'
                
                if 'Canary found' in checksec_output:
                    protections['Canary'] = 'YES'
                elif 'No canary found' in checksec_output:
                    protections['Canary'] = 'NO'
                
                if 'Full RELRO' in checksec_output:
                    protections['RELRO'] = 'FULL'
                elif 'Partial RELRO' in checksec_output:
                    protections['RELRO'] = 'PARTIAL'
                elif 'No RELRO' in checksec_output:
                    protections['RELRO'] = 'NO'
        except:
            pass
        
        if protections['Canary'] == 'Unknown':
            result = self.run_command(['readelf', '-s', self.binary])
            if result['success']:
                if '__stack_chk_fail' in result['stdout'] or '__stack_chk_guard' in result['stdout']:
                    protections['Canary'] = 'YES'
                else:
                    protections['Canary'] = 'NO'
        
        if protections['PIE'] == 'Unknown':
            result = self.run_command(['readelf', '-h', self.binary])
            if result['success']:
                if 'DYN' in result['stdout']:
                    protections['PIE'] = 'YES'
                else:
                    protections['PIE'] = 'NO'
        
        if protections['NX'] == 'Unknown':
            result = self.run_command(['readelf', '-l', self.binary])
            if result['success']:
                if 'GNU_STACK' in result['stdout']:
                    if 'RWE' in result['stdout']:
                        protections['NX'] = 'NO'
                    else:
                        protections['NX'] = 'YES'
        
        return protections

    def get_functions(self):
        functions = []
        result = self.run_command(['nm', self.binary])
        if result['success']:
            lines = result['stdout'].split('\n')
            for line in lines:
                interesting = [
                    'system', 'exec', 'strcpy', 'strcat', 'gets', 'scanf',
                    'printf', 'sprintf', 'malloc', 'free', 'read', 'write',
                    'open', 'close', 'win', 'flag', 'vuln', 'main', 'echo',
                    'bof', 'overflow', 'shell', 'backdoor', 'vulnerable'
                ]
                for func in interesting:
                    if func in line.lower():
                        parts = line.split()
                        if len(parts) >= 3:
                            functions.append({
                                'address': parts[0],
                                'name': parts[2],
                                'type': parts[1]
                            })
        if not functions:
            result = self.run_command(['objdump', '-t', self.binary])
            if result['success']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if '.text' in line and 'F' in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            func_name = parts[-1]
                            functions.append({
                                'address': parts[0],
                                'name': func_name,
                                'type': 'function'
                            })
        return functions[:50]

    def get_imports(self):
        imports = []
        result = self.run_command(['readelf', '-s', self.binary])
        if result['success']:
            lines = result['stdout'].split('\n')
            for line in lines:
                if 'UND' in line or 'GLOBAL' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        imports.append({
                            'address': parts[1] if len(parts[1]) == 16 or len(parts[1]) == 8 else '0',
                            'type': parts[3],
                            'name': parts[-1]
                        })
        return imports[:20]

    def get_sections(self):
        sections = []
        result = self.run_command(['readelf', '-S', self.binary])
        if result['success']:
            lines = result['stdout'].split('\n')
            for line in lines[3:]:
                parts = line.split()
                if len(parts) >= 7:
                    sections.append({
                        'name': parts[1],
                        'type': parts[2],
                        'address': parts[3],
                        'offset': parts[4],
                        'size': parts[5]
                    })
        return sections[:10]

    def get_entry_point(self):
        result = self.run_command(['readelf', '-h', self.binary])
        if result['success']:
            for line in result['stdout'].split('\n'):
                if 'Entry point address:' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        return parts[1].strip()
        return 'unknown'

    def disassemble(self):
        result = self.run_command(['objdump', '-d', '--no-show-raw-insn', self.binary])
        if result['success']:
            self.disassembly = result['stdout']
        else:
            self.disassembly = "Failed to disassemble"

    def analyze_control_flow(self):
        if not self.disassembly:
            self.disassemble()
        
        lines = self.disassembly.split('\n')
        current_function = None
        for line in lines:
            if '>:' in line and '<' in line:
                match = re.search(r'<([^>]+)>:', line)
                if match:
                    current_function = match.group(1)
            elif current_function and ('call' in line or 'jmp' in line or 'je' in line or 'jne' in line or 'jz' in line or 'jnz' in line):
                parts = line.strip().split()
                if len(parts) >= 2:
                    target = parts[-1]
                    self.control_flow.append({
                        'from': current_function,
                        'to': target,
                        'instruction': line.strip()
                    })

class InteractiveVulnerabilityDetector:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.runner = BinaryRunner(binary_path)
        self.results = {
            'buffer_overflow': [],
            'format_string': [],
            'integer_overflow': [],
            'interactive_crashes': []
        }
        self.stop_flag = False
        self.interaction_patterns = []

    def discover_interactions(self):
        test_inputs = [
            b'',
            b'\n',
            b'A' * 10 + b'\n',
            b'1\n',
            b'help\n',
            b'?\n',
            b'test\n',
            b'AAAA\n',
            b'quit\n',
            b'exit\n'
        ]

        for inp in test_inputs:
            if self.stop_flag:
                break
            result = self.runner.run_with_input(inp, timeout=2)
            if result.get('success'):
                output = result.get('output', '')
                if ':' in output or '?' in output or '>' in output or '>>' in output:
                    lines = output.split('\n')
                    for line in lines:
                        if ':' in line and len(line) < 100:
                            prompt = line.strip()
                            if prompt and prompt not in self.interaction_patterns:
                                self.interaction_patterns.append(prompt)

        if not self.interaction_patterns:
            self.interaction_patterns = ["Enter input:", ">", ":", ">>", "input:"]

        return self.interaction_patterns

    def detect_interactive_vulnerabilities(self):
        self.discover_interactions()
        test_cases = self.generate_interactive_test_cases()

        for test_name, inputs in test_cases:
            if self.stop_flag:
                break
            result = self.runner.run_interactive(inputs, timeout=5)

            if result.get('crashed'):
                self.results['interactive_crashes'].append({
                    'test': test_name,
                    'inputs': inputs,
                    'signal': 'SIGSEGV' if result['returncode'] == -11 else 'SIGABRT' if result['returncode'] == -6 else 'Unknown',
                    'output': result.get('output', '')[:500]
                })

        self.detect_buffer_overflow_interactive()
        self.detect_format_string_interactive()

        return self.results

    def generate_interactive_test_cases(self):
        test_cases = []

        for pattern in self.interaction_patterns:
            if '?' in pattern or 'help' in pattern.lower():
                test_cases.append(("Help menu", [b'help\n', b'?\n']))

            if ':' in pattern and 'level' in pattern.lower():
                test_cases.append(("Level selection", [b'1\n', b'A' * 100 + b'\n']))
                test_cases.append(("Level overflow", [b'999999\n', b'-1\n']))

            if ':' in pattern and ('text' in pattern.lower() or 'input' in pattern.lower() or 'enter' in pattern.lower()):
                test_cases.append(("Small input", [b'test\n']))
                test_cases.append(("Medium overflow", [b'A' * 500 + b'\n']))
                test_cases.append(("Large overflow", [b'A' * 2000 + b'\n']))
                test_cases.append(("Format string", [b'%x ' * 50 + b'\n']))
                test_cases.append(("Format string %n", [b'%n' * 20 + b'\n']))

        if not test_cases:
            test_cases = [
                ("Default test 1", [b'1\n', b'A' * 100 + b'\n']),
                ("Default test 2", [b'2\n', b'A' * 500 + b'\n']),
                ("Default test 3", [b'3\n', b'A' * 2000 + b'\n']),
                ("Default format", [b'1\n', b'%x ' * 100 + b'\n']),
            ]

        return test_cases

    def detect_buffer_overflow_interactive(self):
        for pattern in self.interaction_patterns:
            if ':' in pattern:
                for length in [100, 200, 500, 1000, 2000]:
                    if self.stop_flag:
                        break

                    pattern_input = PatternGenerator.create(length)
                    inputs = []

                    if 'level' in pattern.lower():
                        inputs.append(b'1\n')

                    inputs.append(pattern_input.encode() + b'\n')

                    result = self.runner.run_interactive(inputs, timeout=3)

                    if result.get('crashed'):
                        crash_info = {
                            'type': 'buffer_overflow',
                            'interaction': pattern,
                            'length': length,
                            'crashed': True,
                            'signal': 'SIGSEGV' if result['returncode'] == -11 else 'Unknown'
                        }

                        if result.get('output'):
                            output = result['output']
                            if '4141' in output or '4242' in output or '4343' in output:
                                crash_info['pattern_detected'] = True

                        self.results['buffer_overflow'].append(crash_info)
                        break

    def detect_format_string_interactive(self):
        for pattern in self.interaction_patterns:
            if ':' in pattern and ('text' in pattern.lower() or 'input' in pattern.lower()):
                format_tests = [
                    (b'%x ' * 100 + b'\n', "Memory leak test"),
                    (b'%p ' * 50 + b'\n', "Pointer leak test"),
                    (b'%s\n', "String leak test"),
                    (b'%n' * 10 + b'\n', "Write test"),
                ]

                for payload, desc in format_tests:
                    if self.stop_flag:
                        break

                    inputs = []
                    if 'level' in pattern.lower():
                        inputs.append(b'1\n')

                    inputs.append(payload)

                    result = self.runner.run_interactive(inputs, timeout=3)

                    if result.get('success'):
                        output = result['output']
                        if '41414141' in output or '0x' in output and '7f' in output:
                            self.results['format_string'].append({
                                'type': 'format_string',
                                'interaction': pattern,
                                'test': desc,
                                'leak_detected': True,
                                'output_sample': output[:200]
                            })

                    if result.get('crashed') and '%n' in payload.decode('latin-1', errors='ignore'):
                        self.results['format_string'].append({
                            'type': 'format_string',
                            'interaction': pattern,
                            'test': desc,
                            'crash_detected': True,
                            'signal': 'SIGSEGV'
                        })

    def stop(self):
        self.stop_flag = True
        self.runner.kill()

class Fuzzer:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.runner = BinaryRunner(binary_path)
        self.crashes = []
        self.hangs = []
        self.coverage = set()
        self.stop_flag = False

    def generate_test_cases(self):
        test_cases = []
        
        strings = [
            "",
            "A",
            "AAAA",
            "A" * 100,
            "A" * 1000,
            "A" * 10000,
            "%s" * 100,
            "%p" * 50,
            "%n" * 20,
            "\\x00" * 10,
            "\\xff" * 10,
            "../../etc/passwd",
            "|| ls",
            "; ls;",
            "`ls`",
            "$(ls)",
            "<script>alert(1)</script>",
            "\"'",
            "\\",
            "\n",
            "\r\n",
            "\t",
            "\x00",
            "\xff",
        ]
        
        numbers = [
            "0",
            "1",
            "-1",
            "2147483647",
            "-2147483648",
            "4294967295",
            "999999999999",
            "0.1",
            "-0.1",
            "1.0e10",
            "NaN",
            "Infinity",
        ]
        
        for s in strings:
            test_cases.append(s.encode())
        
        for n in numbers:
            test_cases.append(n.encode())
        
        for i in range(100):
            length = random.randint(1, 10000)
            test_cases.append(b'A' * length)
            test_cases.append(b'%x ' * (length // 2))
        
        return test_cases

    def fuzz(self, max_cases=1000):
        test_cases = self.generate_test_cases()
        
        for i, test_case in enumerate(test_cases[:max_cases]):
            if self.stop_flag:
                break
            
            result = self.runner.run_with_input(test_case, timeout=2)
            
            if result.get('timeout'):
                self.hangs.append({
                    'input': test_case[:100],
                    'length': len(test_case)
                })
            
            if result.get('crashed'):
                self.crashes.append({
                    'input': test_case[:100],
                    'length': len(test_case),
                    'returncode': result.get('returncode'),
                    'output': result.get('stdout', '')[:200]
                })
            
            if result.get('success') and result.get('stdout'):
                output_hash = hashlib.md5(result['stdout'].encode()).hexdigest()
                self.coverage.add(output_hash)
        
        return {
            'crashes': self.crashes,
            'hangs': self.hangs,
            'coverage': len(self.coverage),
            'total_tests': min(max_cases, len(test_cases))
        }

    def stop(self):
        self.stop_flag = True
        self.runner.kill()

class VulnerabilityDetector:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary = None
        self.results = {
            'buffer_overflow': [],
            'format_string': [],
            'integer_overflow': [],
            'command_injection': [],
            'race_conditions': [],
            'heap_vulnerabilities': [],
            'info_leaks': [],
            'static_analysis': []
        }
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.arch = 'x86'
        self.bits = 32
        self.disassembly = ""

    def _load_vulnerability_patterns(self):
        patterns = {
            'buffer_overflow': [
                r'strcpy\s*\([^,]+,\s*[^)]+\)',
                r'strcat\s*\([^,]+,\s*[^)]+\)',
                r'gets\s*\([^)]+\)',
                r'scanf\s*\([^,]+,\s*[^)]+\)',
                r'read\s*\([^,]+,\s*[^,]+,\s*[0-9]+\)',
                r'fgets\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
                r'memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
                r'memmove\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
            ],
            'format_string': [
                r'printf\s*\([^"]+[^)]+\)',
                r'sprintf\s*\([^,]+,\s*[^"]+[^)]+\)',
                r'fprintf\s*\([^,]+,\s*[^"]+[^)]+\)',
                r'vprintf\s*\([^"]+[^)]+\)',
                r'snprintf.*%[npsx]',
            ],
            'integer_overflow': [
                r'\+\+[a-zA-Z_][a-zA-Z0-9_]*',
                r'[a-zA-Z_][a-zA-Z0-9_]*\s*\+=\s*[0-9]+',
                r'malloc\s*\([a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[0-9]+\)',
                r'calloc\s*\([a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[0-9]+\)',
            ],
            'command_injection': [
                r'system\s*\([^)]+\)',
                r'popen\s*\([^)]+\)',
                r'exec[lv]?[lp]?\s*\([^)]+\)',
                r'spawn[lv]?[lp]?\s*\([^)]+\)',
            ],
            'heap_vulnerabilities': [
                r'malloc\s*\([^)]+\)',
                r'free\s*\([^)]+\)',
                r'calloc\s*\([^)]+\)',
                r'realloc\s*\([^)]+\)',
            ],
            'info_leaks': [
                r'puts\s*\([^)]+\)',
                r'write\s*\([^,]+,\s*[^,]+,\s*[0-9]+\)',
                r'send\s*\([^,]+,\s*[^,]+,\s*[0-9]+\)',
            ]
        }
        return patterns

    def analyze_statically(self):
        self._detect_architecture()
        self._disassemble_binary()
        self._scan_for_vulnerabilities()
        self._analyze_control_flow_vulnerabilities()
        self._check_protections()
        self._find_dangerous_functions()
        self._analyze_strings()
        return self.results

    def _detect_architecture(self):
        try:
            result = subprocess.run(['file', self.binary_path], 
                                  capture_output=True, text=True)
            output = result.stdout.lower()
            if '64-bit' in output or 'x86-64' in output:
                self.arch = 'x64'
                self.bits = 64
            elif '32-bit' in output or '80386' in output:
                self.arch = 'x86'
                self.bits = 32
            elif 'arm' in output:
                self.arch = 'arm'
                self.bits = 32 if '32' in output else 64
            elif 'mips' in output:
                self.arch = 'mips'
                self.bits = 32
        except Exception as e:
            pass

    def _disassemble_binary(self):
        try:
            result = subprocess.run(['objdump', '-d', self.binary_path],
                                  capture_output=True, text=True, timeout=30)
            self.disassembly = result.stdout
        except:
            self.disassembly = ""

    def _scan_for_vulnerabilities(self):
        lines = self.disassembly.split('\n')
        current_function = None
        function_start = 0
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            if '>:' in line and '<' in line:
                match = re.search(r'<([^>]+)>:', line)
                if match:
                    current_function = match.group(1)
                    function_start = i
            
            if 'lea' in line_lower and ('rbp' in line_lower or 'ebp' in line_lower):
                match = re.search(r'\[rbp-([0-9a-fx]+)\]', line_lower)
                if not match:
                    match = re.search(r'\[ebp-([0-9a-fx]+)\]', line_lower)
                
                if match:
                    try:
                        offset = int(match.group(1), 16) if '0x' in match.group(1) else int(match.group(1))
                        if offset < 256:
                            for j in range(i, min(i+20, len(lines))):
                                next_line = lines[j].lower()
                                if ('call' in next_line and 
                                    any(func in next_line for func in ['strcpy', 'strcat', 'gets', 'scanf'])):
                                    self.results['buffer_overflow'].append({
                                        'function': current_function or 'unknown',
                                        'offset': offset,
                                        'line': line.strip(),
                                        'call_line': lines[j].strip(),
                                        'severity': 'high',
                                        'description': f'Potential buffer overflow in {current_function} with offset {offset}'
                                    })
                                    break
                    except:
                        pass
            
            if 'call' in line_lower and any(func in line_lower for func in ['printf', 'sprintf', 'fprintf', 'snprintf']):
                for j in range(max(0, i-10), i):
                    prev_line = lines[j].lower()
                    if 'lea' in prev_line or 'mov' in prev_line:
                        if '[rbp' in prev_line or '[ebp' in prev_line or 'rdi' in prev_line or 'edi' in prev_line:
                            self.results['format_string'].append({
                                'function': current_function or 'unknown',
                                'line': line.strip(),
                                'severity': 'medium',
                                'description': f'Potential format string vulnerability in {current_function}'
                            })
                            break
            
            if any(op in line_lower for op in ['add ', 'inc ', 'mul ', 'imul']):
                if 'eax' in line_lower or 'rax' in line_lower:
                    self.results['integer_overflow'].append({
                        'function': current_function or 'unknown',
                        'line': line.strip(),
                        'severity': 'medium',
                        'description': f'Potential integer overflow in {current_function}'
                    })
            
            if 'call' in line_lower and 'system' in line_lower:
                self.results['command_injection'].append({
                    'function': current_function or 'unknown',
                    'line': line.strip(),
                    'severity': 'critical',
                    'description': f'System call detected in {current_function} - possible command injection'
                })

    def _analyze_control_flow_vulnerabilities(self):
        lines = self.disassembly.split('\n')
        current_function = None
        basic_blocks = []
        current_block = []
        
        for line in lines:
            if '>:' in line and '<' in line:
                if current_block and current_function:
                    basic_blocks.append((current_function, current_block))
                match = re.search(r'<([^>]+)>:', line)
                if match:
                    current_function = match.group(1)
                current_block = []
            
            if line.strip() and not line.strip().endswith(':'):
                current_block.append(line.strip())
        
        for func_name, block in basic_blocks:
            block_text = '\n'.join(block)
            
            if 'free' in block_text and any(reg in block_text for reg in ['mov', 'lea', 'add']):
                self.results['heap_vulnerabilities'].append({
                    'function': func_name,
                    'type': 'use_after_free',
                    'severity': 'high',
                    'description': f'Potential use-after-free in {func_name}',
                    'code_snippet': block_text[:200]
                })
            
            free_count = block_text.count('free')
            if free_count > 1:
                self.results['heap_vulnerabilities'].append({
                    'function': func_name,
                    'type': 'double_free',
                    'severity': 'high',
                    'description': f'Potential double free in {func_name}',
                    'code_snippet': block_text[:200]
                })

    def _check_protections(self):
        try:
            result = subprocess.run(['checksec', '--file=' + self.binary_path],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                output = result.stdout
                protections = {
                    'NX': 'NX enabled' in output,
                    'PIE': 'PIE enabled' in output,
                    'Stack Canary': 'Canary found' in output,
                    'RELRO': 'Full RELRO' in output if 'Full RELRO' in output else 'Partial RELRO' in output if 'Partial RELRO' in output else 'No RELRO'
                }
                
                self.results['static_analysis'].append({
                    'type': 'security_protections',
                    'data': protections,
                    'description': 'Binary security protections analysis'
                })
                
                if not protections.get('Stack Canary', True):
                    for vuln in self.results['buffer_overflow']:
                        vuln['severity'] = 'critical'
                        vuln['description'] += ' (NO STACK CANARY)'
        except:
            pass

    def _find_dangerous_functions(self):
        dangerous_funcs = [
            'strcpy', 'strcat', 'gets', 'scanf', 'printf', 'sprintf',
            'system', 'exec', 'popen', 'malloc', 'free', 'strncpy',
            'memcpy', 'strlen', 'read', 'write', 'open', 'close'
        ]
        
        for func in dangerous_funcs:
            pattern = rf'call.*{func}'
            matches = re.findall(pattern, self.disassembly, re.IGNORECASE)
            if matches:
                self.results['static_analysis'].append({
                    'type': 'dangerous_function',
                    'function': func,
                    'count': len(matches),
                    'description': f'Found {len(matches)} calls to {func}()',
                    'severity': 'high' if func in ['strcpy', 'gets', 'system'] else 'medium'
                })

    def _analyze_strings(self):
        try:
            result = subprocess.run(['strings', self.binary_path],
                                  capture_output=True, text=True)
            
            strings = result.stdout.split('\n')
            
            format_strings = [s for s in strings if '%' in s and any(f in s for f in ['%s', '%d', '%x', '%n', '%p'])]
            
            for fmt in format_strings[:10]:
                self.results['format_string'].append({
                    'type': 'format_string_in_binary',
                    'string': fmt,
                    'severity': 'low',
                    'description': f'Format string found in binary: {fmt[:50]}...'
                })
            
            shell_patterns = ['/bin/sh', '/bin/bash', 'sh', 'bash', 'cmd.exe', 'powershell']
            for pattern in shell_patterns:
                for s in strings:
                    if pattern in s.lower():
                        self.results['command_injection'].append({
                            'type': 'shell_string',
                            'string': s,
                            'severity': 'medium',
                            'description': f'Shell string found: {s[:50]}...'
                        })
                        break
        except:
            pass

    def perform_recursive_analysis(self, depth=3):
        self.analyze_statically()
        self._analyze_function_chains(depth)
        self._analyze_data_flow()
        self._simulate_taint_analysis()
        return self.results

    def _analyze_function_chains(self, depth):
        call_pattern = r'call\s+([0-9a-f]+)\s+<([^>]+)>'
        calls = re.findall(call_pattern, self.disassembly)
        
        call_graph = {}
        current_func = None
        
        lines = self.disassembly.split('\n')
        for line in lines:
            if '>:' in line and '<' in line:
                match = re.search(r'<([^>]+)>:', line)
                if match:
                    current_func = match.group(1)
                    call_graph[current_func] = []
            elif 'call' in line.lower():
                match = re.search(r'call\s+[0-9a-f]+\s+<([^>]+)>', line)
                if match and current_func:
                    called_func = match.group(1)
                    call_graph[current_func].append(called_func)
        
        vulnerable_chains = self._find_vulnerable_chains(call_graph, depth)
        
        for chain in vulnerable_chains:
            self.results['static_analysis'].append({
                'type': 'vulnerable_call_chain',
                'chain': ' -> '.join(chain),
                'severity': 'medium',
                'description': f'Potential vulnerable call chain: {" -> ".join(chain)}'
            })

    def _find_vulnerable_chains(self, graph, max_depth):
        vulnerable_chains = []
        dangerous_sources = ['main', 'vuln', 'handle_client', 'process_input']
        dangerous_sinks = ['strcpy', 'gets', 'system', 'printf']
        
        for source in dangerous_sources:
            if source in graph:
                chains = self._dfs_find_chains(graph, source, dangerous_sinks, max_depth)
                vulnerable_chains.extend(chains)
        
        return vulnerable_chains

    def _dfs_find_chains(self, graph, current, sinks, depth, path=None, visited=None):
        if path is None:
            path = []
        if visited is None:
            visited = set()
        
        if depth <= 0 or current in visited:
            return []
        
        path = path + [current]
        visited.add(current)
        
        chains = []
        
        if any(sink in current.lower() for sink in sinks):
            chains.append(path)
        
        if current in graph:
            for neighbor in graph[current]:
                if neighbor not in visited:
                    new_chains = self._dfs_find_chains(graph, neighbor, sinks, depth-1, path, visited.copy())
                    chains.extend(new_chains)
        
        return chains

    def _analyze_data_flow(self):
        lines = self.disassembly.split('\n')
        
        sources = []
        sinks = []
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            if any(src in line_lower for src in ['read', 'recv', 'fgets', 'scanf']):
                sources.append((i, line.strip()))
            
            if any(sink in line_lower for sink in ['strcpy', 'system', 'printf']):
                sinks.append((i, line.strip()))
        
        for src_idx, src_line in sources:
            for sink_idx, sink_line in sinks:
                if sink_idx > src_idx and sink_idx - src_idx < 50:
                    self.results['static_analysis'].append({
                        'type': 'data_flow',
                        'source': src_line,
                        'sink': sink_line,
                        'distance': sink_idx - src_idx,
                        'severity': 'medium',
                        'description': f'Potential data flow from {src_line} to {sink_line}'
                    })

    def _simulate_taint_analysis(self):
        lines = self.disassembly.split('\n')
        tainted_registers = set()
        tainted_memory = set()
        
        for i, line in enumerate(lines):
            line_lower = line.lower().strip()
            
            if any(src in line_lower for src in ['read', 'recv', 'fgets']):
                if 'rax' in line_lower or 'eax' in line_lower:
                    tainted_registers.add('rax' if 'rax' in line_lower else 'eax')
                elif 'rdi' in line_lower or 'edi' in line_lower:
                    tainted_registers.add('rdi' if 'rdi' in line_lower else 'edi')
            
            if 'mov' in line_lower:
                parts = line_lower.split(',')
                if len(parts) == 2:
                    src, dst = parts
                    src = src.strip()
                    dst = dst.strip()
                    
                    if any(reg in src for reg in tainted_registers) or any(mem in src for mem in tainted_memory):
                        if '[' in dst and ']' in dst:
                            tainted_memory.add(dst)
                        elif any(reg in dst for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp',
                                                       'eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp']):
                            reg = re.findall(r'[re]?[abcd]x|[re]?[sd]i|[re]?[sb]p', dst)
                            if reg:
                                tainted_registers.add(reg[0])
            
            if any(sink in line_lower for sink in ['strcpy', 'system', 'printf']):
                args = line_lower[line_lower.find('(')+1:line_lower.find(')')] if '(' in line_lower else ''
                if any(reg in args for reg in tainted_registers) or any(mem in args for mem in tainted_memory):
                    self.results['static_analysis'].append({
                        'type': 'taint_analysis',
                        'line': line.strip(),
                        'severity': 'high',
                        'description': f'Tainted data reaches dangerous function at line {i}: {line.strip()}',
                        'tainted_registers': list(tainted_registers),
                        'tainted_memory': list(tainted_memory)[:5]
                    })

class ExploitGenerator:
    @staticmethod
    def generate_buffer_overflow_exploit(offset, arch='x64'):
        if arch == 'x86':
            exploit = f"""#!/usr/bin/env python3
import struct
import subprocess

binary = "./binary"
offset = {offset}

payload = b"A" * offset
payload += struct.pack("<I", 0xdeadbeef)
print(f"Payload length: {{len(payload)}}")
print(f"Payload hex: {{payload.hex()}}")

p = subprocess.Popen([binary], stdin=subprocess.PIPE)
p.communicate(input=payload)"""
        else:
            exploit = f"""#!/usr/bin/env python3
import struct
import subprocess

binary = "./binary"
offset = {offset}

payload = b"A" * offset
payload += struct.pack("<Q", 0xdeadbeefcafebabe)
print(f"Payload length: {{len(payload)}}")
print(f"Payload hex: {{payload.hex()}}")

p = subprocess.Popen([binary], stdin=subprocess.PIPE)
p.communicate(input=payload)"""
        return exploit

    @staticmethod
    def generate_format_string_exploit(offset):
        exploit = f"""#!/usr/bin/env python3
binary = "./binary"

payload = f"%{offset}$p"
print(f"Payload: {{payload}}")

import subprocess
p = subprocess.Popen([binary], stdin=subprocess.PIPE)
p.communicate(input=payload.encode())"""
        return exploit

    @staticmethod
    def generate_rop_exploit(arch='x64'):
        if arch == 'x86':
            exploit = """#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

binary = "./binary"
elf = ELF(binary)

rop = ROP(elf)
rop.system(next(elf.search(b'/bin/sh')))
print(rop.dump())

payload = fit({{
    44: rop.chain()
}})

io = process(binary)
io.sendline(payload)
io.interactive()"""
        else:
            exploit = """#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

binary = "./binary"
elf = ELF(binary)

rop = ROP(elf)
rop.system(next(elf.search(b'/bin/sh')))
print(rop.dump())

payload = fit({{
    72: rop.chain()
}})

io = process(binary)
io.sendline(payload)
io.interactive()"""
        return exploit

class CTFPwnTool:
    def __init__(self, root):
        self.root = root
        self.root.title("ADVANCED CTF PWN TOOL")
        self.root.geometry("1400x900")
        self.binary_path = ""
        self.analyzer = None
        self.detector = None
        self.vuln_detector = None
        self.fuzzer = None
        self.current_results = None
        self.setup_gui()

    def setup_gui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        header = tk.Frame(self.root, bg='#2c3e50', height=70)
        header.grid(row=0, column=0, sticky='ew', padx=10, pady=10)
        header.grid_propagate(False)

        title = tk.Label(header, text="🚀 ADVANCED CTF PWN TOOL",
                        font=('Courier', 20, 'bold'), bg='#2c3e50', fg='white')
        title.pack(pady=20)

        main_container = tk.Frame(self.root)
        main_container.grid(row=1, column=0, sticky='nsew', padx=10, pady=5)

        left_panel = tk.Frame(main_container, width=250, bg='#34495e')
        left_panel.pack(side='left', fill='y')
        left_panel.pack_propagate(False)

        control_frame = tk.Frame(left_panel, bg='#34495e')
        control_frame.pack(fill='x', pady=20)

        buttons = [
            ("📁 Load Binary", self.load_binary),
            ("🔍 Analyze Binary", self.analyze_binary),
            ("🔬 Static Vuln Detect", self.detect_vulnerabilities_static),
            ("💣 Interactive Detect", self.detect_interactive),
            ("🎯 Start Fuzzing", self.start_fuzzing),
            ("🔄 Recursive Analysis", self.recursive_analysis),
            ("⚡ Generate Exploit", self.generate_exploit),
            ("📊 View Results", self.show_results),
            ("💾 Export", self.export_results),
            ("📈 Statistics", self.show_statistics),
        ]

        for text, command in buttons:
            btn = tk.Button(control_frame, text=text, command=command,
                          bg='#3498db', fg='white', font=('Arial', 10),
                          width=22, anchor='w', padx=10)
            btn.pack(pady=3, padx=10)

        info_frame = tk.Frame(left_panel, bg='#2c3e50', relief=tk.RAISED, borderwidth=1)
        info_frame.pack(fill='x', pady=20, padx=10)

        self.binary_label = tk.Label(info_frame, text="No binary loaded",
                                    bg='#2c3e50', fg='white', wraplength=220)
        self.binary_label.pack(pady=10, padx=10)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(left_panel, textvariable=self.status_var,
                            bg='#2c3e50', fg='#ecf0f1', font=('Arial', 9))
        status_bar.pack(side='bottom', fill='x', pady=10)

        right_panel = tk.Frame(main_container)
        right_panel.pack(side='right', fill='both', expand=True)

        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill='both', expand=True)

        self.create_analysis_tab()
        self.create_vulnerabilities_tab()
        self.create_static_analysis_tab()
        self.create_interactive_tab()
        self.create_fuzzing_tab()
        self.create_control_flow_tab()
        self.create_exploit_tab()
        self.create_log_tab()

    def create_analysis_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Analysis")
        self.analysis_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                      font=('Courier', 10))
        self.analysis_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.analysis_text.config(state='disabled')

    def create_vulnerabilities_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Vulnerabilities")
        paned = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(fill='both', expand=True, padx=5, pady=5)
        left_frame = tk.Frame(paned)
        paned.add(left_frame, width=400)
        tk.Label(left_frame, text="Detected Vulnerabilities",
                font=('Arial', 12, 'bold')).pack(anchor='w', pady=10, padx=10)
        self.vuln_listbox = tk.Listbox(left_frame, font=('Courier', 10))
        self.vuln_listbox.pack(fill='both', expand=True, padx=10, pady=10)
        self.vuln_listbox.bind('<<ListboxSelect>>', self.on_vuln_select)
        right_frame = tk.Frame(paned)
        paned.add(right_frame)
        tk.Label(right_frame, text="Vulnerability Details",
                font=('Arial', 12, 'bold')).pack(anchor='w', pady=10, padx=10)
        self.vuln_details = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD,
                                                     font=('Courier', 10))
        self.vuln_details.pack(fill='both', expand=True, padx=10, pady=10)
        self.vuln_details.config(state='disabled')

    def create_static_analysis_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Static Analysis")
        
        control_frame = tk.Frame(frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(control_frame, text="Analysis Depth:").pack(side='left', padx=5)
        self.analysis_depth = tk.IntVar(value=3)
        depth_spin = tk.Spinbox(control_frame, from_=1, to=10, textvariable=self.analysis_depth, width=5)
        depth_spin.pack(side='left', padx=5)
        
        self.start_static_btn = tk.Button(control_frame, text="▶ Start Static Analysis",
                                        command=self.detect_vulnerabilities_static,
                                        bg='#27ae60', fg='white')
        self.start_static_btn.pack(side='left', padx=10)
        
        self.recursive_btn = tk.Button(control_frame, text="🔄 Recursive Analysis",
                                      command=self.recursive_analysis,
                                      bg='#9b59b6', fg='white')
        self.recursive_btn.pack(side='left', padx=5)
        
        paned = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(fill='both', expand=True, padx=5, pady=5)
        
        left_frame = tk.Frame(paned)
        paned.add(left_frame, width=400)
        
        tk.Label(left_frame, text="Detected Vulnerabilities",
                font=('Arial', 12, 'bold')).pack(anchor='w', pady=10, padx=10)
        
        columns = ('Severity', 'Type', 'Function', 'Description')
        self.vuln_tree = ttk.Treeview(left_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side='right', fill='y', padx=(0, 10), pady=10)
        
        self.vuln_tree.bind('<<TreeviewSelect>>', self.on_vuln_tree_select)
        
        right_frame = tk.Frame(paned)
        paned.add(right_frame)
        
        tk.Label(right_frame, text="Vulnerability Details",
                font=('Arial', 12, 'bold')).pack(anchor='w', pady=10, padx=10)
        
        self.static_details = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD,
                                                       font=('Courier', 10))
        self.static_details.pack(fill='both', expand=True, padx=10, pady=10)
        self.static_details.config(state='disabled')

    def create_interactive_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Interactive Analysis")
        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill='x', padx=10, pady=10)
        self.start_interactive_btn = tk.Button(btn_frame, text="▶ Start Interactive Analysis",
                                             command=self.detect_interactive, bg='#27ae60', fg='white')
        self.start_interactive_btn.pack(side='left', padx=5)
        self.stop_interactive_btn = tk.Button(btn_frame, text="⏹ Stop",
                                            command=self.stop_interactive, bg='#e74c3c', fg='white',
                                            state='disabled')
        self.stop_interactive_btn.pack(side='left', padx=5)
        self.interactive_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                         font=('Courier', 10))
        self.interactive_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.interactive_text.config(state='disabled')

    def create_fuzzing_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Fuzzing")
        
        control_frame = tk.Frame(frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(control_frame, text="Max Test Cases:").pack(side='left', padx=5)
        self.fuzz_max_cases = tk.IntVar(value=1000)
        fuzz_spin = tk.Spinbox(control_frame, from_=100, to=10000, textvariable=self.fuzz_max_cases, width=10)
        fuzz_spin.pack(side='left', padx=5)
        
        self.start_fuzzing_btn = tk.Button(control_frame, text="▶ Start Fuzzing",
                                         command=self.start_fuzzing, bg='#e67e22', fg='white')
        self.start_fuzzing_btn.pack(side='left', padx=10)
        
        self.stop_fuzzing_btn = tk.Button(control_frame, text="⏹ Stop Fuzzing",
                                        command=self.stop_fuzzing, bg='#e74c3c', fg='white',
                                        state='disabled')
        self.stop_fuzzing_btn.pack(side='left', padx=5)
        
        self.fuzzing_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                     font=('Courier', 10))
        self.fuzzing_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.fuzzing_text.config(state='disabled')

    def create_control_flow_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Control Flow")
        self.control_flow_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                          font=('Courier', 9))
        self.control_flow_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.control_flow_text.config(state='disabled')

    def create_exploit_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Exploit")
        type_frame = tk.Frame(frame)
        type_frame.pack(fill='x', padx=10, pady=10)
        tk.Label(type_frame, text="Exploit Type:", font=('Arial', 10)).pack(side='left', padx=5)
        self.exploit_type = tk.StringVar(value="buffer_overflow")
        types = [
            ("Buffer Overflow", "buffer_overflow"),
            ("Format String", "format_string"),
            ("ROP Chain", "rop"),
            ("Ret2Libc", "ret2libc")
        ]
        for text, value in types:
            tk.Radiobutton(type_frame, text=text, variable=self.exploit_type,
                          value=value).pack(side='left', padx=5)
        tk.Button(type_frame, text="Generate", command=self.generate_exploit,
                 bg='#9b59b6', fg='white').pack(side='left', padx=20)
        self.exploit_editor = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                       font=('Courier', 10))
        self.exploit_editor.pack(fill='both', expand=True, padx=10, pady=10)

    def create_log_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="Log")
        self.log_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                 font=('Courier', 10))
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.log_text.config(state='disabled')

    def log(self, message):
        self.log_text.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        self.root.update()

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()

    def load_binary(self):
        filename = filedialog.askopenfilename(
            title="Select Binary",
            filetypes=[
                ("Executable files", "*.elf *.exe *.bin *.out"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.binary_path = filename
            self.binary_label.config(text=os.path.basename(filename))
            self.log(f"Loaded binary: {filename}")

    def analyze_binary(self):
        if not self.binary_path:
            messagebox.showerror("Error", "Please load a binary first!")
            return
        self.update_status("Analyzing binary...")
        self.log("Starting binary analysis...")
        def analyze_thread():
            try:
                self.analyzer = AdvancedBinaryAnalyzer(self.binary_path)
                results = self.analyzer.analyze()
                self.root.after(0, self.display_analysis, results)
                self.root.after(0, self.log, "Binary analysis complete!")
                self.root.after(0, self.display_control_flow)
            except Exception as e:
                self.root.after(0, self.log, f"Analysis error: {str(e)}")
            self.root.after(0, lambda: self.update_status("Ready"))
        threading.Thread(target=analyze_thread, daemon=True).start()

    def display_analysis(self, results):
        self.analysis_text.config(state='normal')
        self.analysis_text.delete(1.0, tk.END)
        text = "=== BINARY ANALYSIS REPORT ===\n\n"
        text += "📁 FILE INFORMATION:\n"
        text += "-" * 50 + "\n"
        text += f"{results.get('file_info', 'Unknown')}\n\n"
        arch = results.get('architecture', {})
        text += f"Architecture: {arch.get('arch', 'unknown')} ({arch.get('bits', 0)}-bit)\n"
        text += f"Stripped: {'Yes' if hasattr(self.analyzer, 'stripped') and self.analyzer.stripped else 'No'}\n\n"
        text += "🛡️ SECURITY PROTECTIONS:\n"
        text += "-" * 50 + "\n"
        for prot, value in results.get('protections', {}).items():
            icon = "✅" if value == 'NO' else "❌" if value == 'YES' else "❓"
            text += f"{prot}: {value} {icon}\n"
        text += "\n"
        text += "🔧 INTERESTING FUNCTIONS:\n"
        text += "-" * 50 + "\n"
        functions = results.get('functions', [])
        if functions:
            for func in functions[:20]:
                text += f"{func.get('address', ''):10} {func.get('name', '')}\n"
        else:
            text += "No interesting functions found\n"
        text += "\n"
        text += "📥 IMPORTS:\n"
        text += "-" * 50 + "\n"
        imports = results.get('imports', [])
        if imports:
            for imp in imports[:15]:
                text += f"{imp.get('address', ''):10} {imp.get('name', '')}\n"
        else:
            text += "No imports found\n"
        text += "\n"
        text += "📊 SECTIONS:\n"
        text += "-" * 50 + "\n"
        sections = results.get('sections', [])
        if sections:
            for sec in sections[:10]:
                text += f"{sec.get('name', ''):15} {sec.get('address', '')} {sec.get('size', '')}\n"
        else:
            text += "No sections found\n"
        text += "\n"
        text += "🎯 ENTRY POINT:\n"
        text += "-" * 50 + "\n"
        text += f"{results.get('entry_point', 'unknown')}\n"
        self.analysis_text.insert(tk.END, text)
        self.analysis_text.config(state='disabled')

    def detect_vulnerabilities_static(self):
        if not self.binary_path:
            messagebox.showerror("Error", "Please load a binary first!")
            return
        
        self.update_status("Static vulnerability detection...")
        self.log("Starting static vulnerability detection...")
        
        def detect_thread():
            try:
                self.vuln_detector = VulnerabilityDetector(self.binary_path)
                results = self.vuln_detector.analyze_statically()
                
                self.root.after(0, self.display_static_results, results)
                self.root.after(0, self.update_vuln_tree, results)
                self.root.after(0, self.log, "Static vulnerability detection complete!")
                
            except Exception as e:
                self.root.after(0, self.log, f"Static detection error: {str(e)}")
            
            self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=detect_thread, daemon=True).start()

    def recursive_analysis(self):
        if not self.binary_path:
            messagebox.showerror("Error", "Please load a binary first!")
            return
        
        depth = self.analysis_depth.get()
        self.update_status(f"Recursive analysis (depth={depth})...")
        self.log(f"Starting recursive vulnerability analysis (depth={depth})...")
        
        def analyze_thread():
            try:
                self.vuln_detector = VulnerabilityDetector(self.binary_path)
                results = self.vuln_detector.perform_recursive_analysis(depth)
                
                self.root.after(0, self.display_static_results, results)
                self.root.after(0, self.update_vuln_tree, results)
                self.root.after(0, self.log, f"Recursive analysis complete (depth={depth})!")
                
            except Exception as e:
                self.root.after(0, self.log, f"Recursive analysis error: {str(e)}")
            
            self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=analyze_thread, daemon=True).start()

    def display_static_results(self, results):
        self.static_details.config(state='normal')
        self.static_details.delete(1.0, tk.END)
        
        text = "=== STATIC VULNERABILITY ANALYSIS ===\n\n"
        
        total_vulns = sum(len(v) for v in results.values())
        text += f"📊 SUMMARY: Found {total_vulns} potential vulnerabilities\n\n"
        
        if results.get('buffer_overflow'):
            text += "💣 BUFFER OVERFLOWS:\n"
            text += "-" * 50 + "\n"
            for i, vuln in enumerate(results['buffer_overflow'][:10], 1):
                text += f"{i}. Severity: {vuln.get('severity', 'unknown')}\n"
                text += f"   Function: {vuln.get('function', 'unknown')}\n"
                text += f"   Description: {vuln.get('description', '')}\n"
                if 'line' in vuln:
                    text += f"   Line: {vuln.get('line', '')}\n"
                text += "\n"
        
        if results.get('format_string'):
            text += "📝 FORMAT STRING VULNERABILITIES:\n"
            text += "-" * 50 + "\n"
            for i, vuln in enumerate(results['format_string'][:10], 1):
                text += f"{i}. Severity: {vuln.get('severity', 'unknown')}\n"
                text += f"   Function: {vuln.get('function', 'unknown')}\n"
                text += f"   Description: {vuln.get('description', '')}\n"
                if 'line' in vuln:
                    text += f"   Line: {vuln.get('line', '')}\n"
                text += "\n"
        
        if results.get('command_injection'):
            text += "⚡ COMMAND INJECTION:\n"
            text += "-" * 50 + "\n"
            for i, vuln in enumerate(results['command_injection'][:10], 1):
                text += f"{i}. Severity: {vuln.get('severity', 'unknown')}\n"
                text += f"   Function: {vuln.get('function', 'unknown')}\n"
                text += f"   Description: {vuln.get('description', '')}\n"
                if 'line' in vuln:
                    text += f"   Line: {vuln.get('line', '')}\n"
                text += "\n"
        
        if results.get('heap_vulnerabilities'):
            text += "🗑️ HEAP VULNERABILITIES:\n"
            text += "-" * 50 + "\n"
            for i, vuln in enumerate(results['heap_vulnerabilities'][:10], 1):
                text += f"{i}. Type: {vuln.get('type', 'unknown')}\n"
                text += f"   Severity: {vuln.get('severity', 'unknown')}\n"
                text += f"   Function: {vuln.get('function', 'unknown')}\n"
                text += f"   Description: {vuln.get('description', '')}\n"
                text += "\n"
        
        if results.get('static_analysis'):
            text += "🔬 STATIC ANALYSIS FINDINGS:\n"
            text += "-" * 50 + "\n"
            for i, finding in enumerate(results['static_analysis'][:10], 1):
                text += f"{i}. Type: {finding.get('type', 'unknown')}\n"
                text += f"   Severity: {finding.get('severity', 'unknown')}\n"
                text += f"   Description: {finding.get('description', '')}\n"
                if 'data' in finding:
                    text += f"   Data: {finding.get('data', '')}\n"
                text += "\n"
        
        self.static_details.insert(tk.END, text)
        self.static_details.config(state='disabled')

    def update_vuln_tree(self, results):
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        item_id = 0
        
        severity_colors = {
            'critical': '#ff0000',
            'high': '#ff6600',
            'medium': '#ffcc00',
            'low': '#00cc00'
        }
        
        for vuln_type, vuln_list in results.items():
            if vuln_list:
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        severity = vuln.get('severity', 'unknown').lower()
                        if severity not in severity_colors:
                            severity = 'medium'
                        
                        self.vuln_tree.insert('', 'end', 
                                            iid=str(item_id),
                                            values=(
                                                severity.upper(),
                                                vuln_type,
                                                vuln.get('function', 'unknown'),
                                                vuln.get('description', '')[:50] + '...'
                                            ),
                                            tags=(severity,))
                        item_id += 1
        
        for severity, color in severity_colors.items():
            self.vuln_tree.tag_configure(severity, background=color, foreground='white')

    def on_vuln_tree_select(self, event):
        selection = self.vuln_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        item = self.vuln_tree.item(item_id)
        
        if self.vuln_detector and self.vuln_detector.results:
            vuln_index = int(item_id)
            current_index = 0
            
            for vuln_type, vuln_list in self.vuln_detector.results.items():
                if vuln_list:
                    for vuln in vuln_list:
                        if current_index == vuln_index:
                            self.display_vulnerability_details(vuln_type, vuln)
                            return
                        current_index += 1

    def display_vulnerability_details(self, vuln_type, vuln):
        self.static_details.config(state='normal')
        self.static_details.delete(1.0, tk.END)
        
        text = f"=== VULNERABILITY DETAILS ===\n\n"
        text += f"Type: {vuln_type}\n"
        text += f"Severity: {vuln.get('severity', 'unknown')}\n"
        
        for key, value in vuln.items():
            if key not in ['severity']:
                text += f"{key}: {value}\n"
        
        text += "\n🔧 EXPLOIT SUGGESTION:\n"
        if vuln_type == 'buffer_overflow':
            text += "1. Determine exact offset using pattern generator\n"
            text += "2. Overwrite return address with shellcode address\n"
            text += "3. Consider ROP chain if NX is enabled\n"
        elif vuln_type == 'format_string':
            text += "1. Leak stack addresses using %p or %x\n"
            text += "2. Write to arbitrary memory using %n\n"
            text += "3. Overwrite GOT entries or return addresses\n"
        elif vuln_type == 'command_injection':
            text += "1. Inject shell commands through user input\n"
            text += "2. Chain commands with ; or |\n"
            text += "3. Consider privilege escalation\n"
        
        self.static_details.insert(tk.END, text)
        self.static_details.config(state='disabled')

    def display_control_flow(self):
        if not self.analyzer:
            return
        self.control_flow_text.config(state='normal')
        self.control_flow_text.delete(1.0, tk.END)
        text = "=== CONTROL FLOW ANALYSIS ===\n\n"
        if self.analyzer.control_flow:
            current_func = None
            for flow in self.analyzer.control_flow[:100]:
                if flow['from'] != current_func:
                    current_func = flow['from']
                    text += f"\n┌─ Function: {current_func}\n"
                text += f"│  → {flow['to']}\n"
        else:
            text += "No control flow information available\n"
        self.control_flow_text.insert(tk.END, text)
        self.control_flow_text.config(state='disabled')

    def detect_interactive(self):
        if not self.binary_path:
            messagebox.showerror("Error", "Please load a binary first!")
            return
        self.update_status("Interactive detection...")
        self.log("Starting interactive vulnerability detection...")
        self.start_interactive_btn.config(state='disabled')
        self.stop_interactive_btn.config(state='normal')
        def detect_thread():
            try:
                self.detector = InteractiveVulnerabilityDetector(self.binary_path)
                results = self.detector.detect_interactive_vulnerabilities()
                self.current_results = results
                self.root.after(0, self.display_interactive_results, results)
                self.root.after(0, self.log, "Interactive detection complete!")
            except Exception as e:
                self.root.after(0, self.log, f"Detection error: {str(e)}")
            finally:
                self.root.after(0, self.start_interactive_btn.config, {'state': 'normal'})
                self.root.after(0, self.stop_interactive_btn.config, {'state': 'disabled'})
                self.root.after(0, lambda: self.update_status("Ready"))
        threading.Thread(target=detect_thread, daemon=True).start()

    def display_interactive_results(self, results):
        self.interactive_text.config(state='normal')
        self.interactive_text.delete(1.0, tk.END)
        text = "=== INTERACTIVE ANALYSIS RESULTS ===\n\n"
        if results.get('interaction_patterns'):
            text += "Discovered Interaction Patterns:\n"
            for pattern in results['interaction_patterns']:
                text += f"  • {pattern}\n"
            text += "\n"
        if results.get('interactive_crashes'):
            text += "💥 INTERACTIVE CRASHES:\n"
            for crash in results['interactive_crashes']:
                text += f"\nTest: {crash.get('test', 'Unknown')}\n"
                text += f"Inputs: {crash.get('inputs', [])}\n"
                text += f"Signal: {crash.get('signal', 'Unknown')}\n"
                text += f"Output: {crash.get('output', '')[:200]}...\n"
        if results.get('buffer_overflow'):
            text += "\n💣 BUFFER OVERFLOW VULNERABILITIES:\n"
            for vuln in results['buffer_overflow']:
                text += f"\nInteraction: {vuln.get('interaction', 'Unknown')}\n"
                text += f"Length: {vuln.get('length', 'Unknown')}\n"
                text += f"Crashed: {vuln.get('crashed', False)}\n"
        if results.get('format_string'):
            text += "\n📝 FORMAT STRING VULNERABILITIES:\n"
            for vuln in results['format_string']:
                text += f"\nInteraction: {vuln.get('interaction', 'Unknown')}\n"
                text += f"Test: {vuln.get('test', 'Unknown')}\n"
                text += f"Leak Detected: {vuln.get('leak_detected', False)}\n"
                text += f"Crash Detected: {vuln.get('crash_detected', False)}\n"
        if not any([results.get('interactive_crashes'), results.get('buffer_overflow'), results.get('format_string')]):
            text += "No vulnerabilities detected in interactive mode\n"
        self.interactive_text.insert(tk.END, text)
        self.interactive_text.config(state='disabled')
        self.update_vulnerabilities_list(results)

    def update_vulnerabilities_list(self, results):
        self.vuln_listbox.delete(0, tk.END)
        all_vulns = []
        if results.get('buffer_overflow'):
            for vuln in results['buffer_overflow']:
                all_vulns.append(("💣 BUFFER OVERFLOW", vuln))
        if results.get('format_string'):
            for vuln in results['format_string']:
                all_vulns.append(("📝 FORMAT STRING", vuln))
        if results.get('interactive_crashes'):
            for crash in results['interactive_crashes']:
                all_vulns.append(("💥 INTERACTIVE CRASH", crash))
        for vuln_type, data in all_vulns:
            desc = data.get('interaction', data.get('test', 'Unknown'))
            self.vuln_listbox.insert(tk.END, f"{vuln_type}: {desc}")

    def on_vuln_select(self, event):
        selection = self.vuln_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        self.vuln_details.config(state='normal')
        self.vuln_details.delete(1.0, tk.END)
        if self.current_results:
            all_vulns = []
            if self.current_results.get('buffer_overflow'):
                for vuln in self.current_results['buffer_overflow']:
                    all_vulns.append(('buffer_overflow', vuln))
            if self.current_results.get('format_string'):
                for vuln in self.current_results['format_string']:
                    all_vulns.append(('format_string', vuln))
            if self.current_results.get('interactive_crashes'):
                for crash in self.current_results['interactive_crashes']:
                    all_vulns.append(('interactive_crash', crash))
            if index < len(all_vulns):
                vuln_type, data = all_vulns[index]
                text = f"=== VULNERABILITY DETAILS ===\n\n"
                text += f"Type: {vuln_type}\n"
                for key, value in data.items():
                    text += f"{key}: {value}\n"
                self.vuln_details.insert(tk.END, text)
        self.vuln_details.config(state='disabled')

    def stop_interactive(self):
        if self.detector:
            self.detector.stop()
            self.log("Interactive detection stopped")

    def start_fuzzing(self):
        if not self.binary_path:
            messagebox.showerror("Error", "Please load a binary first!")
            return
        
        self.update_status("Starting fuzzing...")
        self.log("Starting fuzzing...")
        self.start_fuzzing_btn.config(state='disabled')
        self.stop_fuzzing_btn.config(state='normal')
        
        def fuzzing_thread():
            try:
                self.fuzzer = Fuzzer(self.binary_path)
                max_cases = self.fuzz_max_cases.get()
                results = self.fuzzer.fuzz(max_cases)
                
                self.root.after(0, self.display_fuzzing_results, results)
                self.root.after(0, self.log, f"Fuzzing complete! Found {len(results['crashes'])} crashes and {len(results['hangs'])} hangs.")
                
            except Exception as e:
                self.root.after(0, self.log, f"Fuzzing error: {str(e)}")
            finally:
                self.root.after(0, self.start_fuzzing_btn.config, {'state': 'normal'})
                self.root.after(0, self.stop_fuzzing_btn.config, {'state': 'disabled'})
                self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=fuzzing_thread, daemon=True).start()

    def display_fuzzing_results(self, results):
        self.fuzzing_text.config(state='normal')
        self.fuzzing_text.delete(1.0, tk.END)
        
        text = "=== FUZZING RESULTS ===\n\n"
        text += f"Total Tests: {results['total_tests']}\n"
        text += f"Unique Outputs: {results['coverage']}\n"
        text += f"Crashes Found: {len(results['crashes'])}\n"
        text += f"Hangs Found: {len(results['hangs'])}\n\n"
        
        if results['crashes']:
            text += "💥 CRASHES:\n"
            text += "-" * 50 + "\n"
            for i, crash in enumerate(results['crashes'][:10], 1):
                text += f"{i}. Input: {crash['input']}\n"
                text += f"   Length: {crash['length']}\n"
                text += f"   Return Code: {crash['returncode']}\n"
                if crash.get('output'):
                    text += f"   Output: {crash['output'][:100]}...\n"
                text += "\n"
        
        if results['hangs']:
            text += "⏰ HANGS:\n"
            text += "-" * 50 + "\n"
            for i, hang in enumerate(results['hangs'][:10], 1):
                text += f"{i}. Input: {hang['input']}\n"
                text += f"   Length: {hang['length']}\n"
                text += "\n"
        
        self.fuzzing_text.insert(tk.END, text)
        self.fuzzing_text.config(state='disabled')

    def stop_fuzzing(self):
        if self.fuzzer:
            self.fuzzer.stop()
            self.log("Fuzzing stopped")

    def generate_exploit(self):
        if not self.current_results and not (self.vuln_detector and self.vuln_detector.results):
            messagebox.showwarning("Warning", "Detect vulnerabilities first!")
            return
        
        exploit_type = self.exploit_type.get()
        arch = 'x64'
        if self.analyzer and self.analyzer.info:
            arch_info = self.analyzer.info.get('architecture', {})
            arch = arch_info.get('arch', 'x64')
        
        offset = 100
        
        if self.vuln_detector and self.vuln_detector.results:
            if exploit_type == "buffer_overflow" and self.vuln_detector.results['buffer_overflow']:
                vuln = self.vuln_detector.results['buffer_overflow'][0]
                if 'offset' in vuln:
                    offset = vuln['offset']
        
        if exploit_type == "buffer_overflow":
            exploit = ExploitGenerator.generate_buffer_overflow_exploit(offset, arch)
        elif exploit_type == "format_string":
            exploit = ExploitGenerator.generate_format_string_exploit(5)
        elif exploit_type == "rop":
            exploit = ExploitGenerator.generate_rop_exploit(arch)
        else:
            exploit = f"# Exploit template for {exploit_type}\n"
        
        self.exploit_editor.delete(1.0, tk.END)
        self.exploit_editor.insert(tk.END, exploit)
        self.log(f"Generated {exploit_type} exploit template")

    def show_results(self):
        if not self.current_results and not (self.vuln_detector and self.vuln_detector.results):
            messagebox.showinfo("Results", "No results yet. Run detection first!")
            return
        
        window = tk.Toplevel(self.root)
        window.title("Results Summary")
        window.geometry("600x500")
        
        text = scrolledtext.ScrolledText(window, wrap=tk.WORD)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        summary = "=== RESULTS SUMMARY ===\n\n"
        
        if self.analyzer and self.analyzer.info:
            summary += "📊 BINARY INFO:\n"
            summary += f"File: {os.path.basename(self.binary_path)}\n"
            arch = self.analyzer.info.get('architecture', {})
            summary += f"Architecture: {arch.get('arch', 'unknown')}\n\n"
        
        total = 0
        vuln_counts = {}
        
        if self.current_results:
            for vuln_type, vuln_list in self.current_results.items():
                if vuln_list:
                    count = len(vuln_list)
                    total += count
                    vuln_counts[vuln_type] = count
        
        if self.vuln_detector and self.vuln_detector.results:
            for vuln_type, vuln_list in self.vuln_detector.results.items():
                if vuln_list:
                    count = len(vuln_list)
                    total += count
                    if vuln_type in vuln_counts:
                        vuln_counts[vuln_type] += count
                    else:
                        vuln_counts[vuln_type] = count
        
        for vuln_type, count in vuln_counts.items():
            summary += f"{vuln_type.replace('_', ' ').title()}: {count}\n"
        
        summary += f"\nTotal Vulnerabilities: {total}\n"
        
        text.insert(tk.END, summary)
        text.config(state='disabled')

    def show_statistics(self):
        if not self.vuln_detector or not self.vuln_detector.results:
            messagebox.showinfo("Statistics", "Run vulnerability detection first!")
            return
        
        window = tk.Toplevel(self.root)
        window.title("Vulnerability Statistics")
        window.geometry("500x400")
        
        text = scrolledtext.ScrolledText(window, wrap=tk.WORD)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        stats_text = "=== VULNERABILITY STATISTICS ===\n\n"
        
        vuln_counts = {}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln_type, vuln_list in self.vuln_detector.results.items():
            if vuln_list:
                vuln_counts[vuln_type] = len(vuln_list)
                for vuln in vuln_list:
                    if isinstance(vuln, dict) and 'severity' in vuln:
                        severity = vuln['severity'].lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
        
        stats_text += "📊 BY TYPE:\n"
        stats_text += "-" * 30 + "\n"
        for vuln_type, count in vuln_counts.items():
            stats_text += f"{vuln_type.replace('_', ' ').title()}: {count}\n"
        
        stats_text += "\n📊 BY SEVERITY:\n"
        stats_text += "-" * 30 + "\n"
        for severity, count in severity_counts.items():
            stats_text += f"{severity.upper()}: {count}\n"
        
        total = sum(vuln_counts.values())
        stats_text += f"\n📈 TOTAL: {total} vulnerabilities\n"
        
        text.insert(tk.END, stats_text)
        text.config(state='disabled')

    def export_results(self):
        if not self.current_results and not (self.vuln_detector and self.vuln_detector.results):
            messagebox.showwarning("Warning", "No results to export!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                data = {
                    'binary': self.binary_path,
                    'timestamp': datetime.now().isoformat(),
                    'analysis': self.analyzer.info if self.analyzer else {},
                    'vulnerabilities': self.current_results if self.current_results else {},
                    'static_analysis': self.vuln_detector.results if self.vuln_detector else {}
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                
                self.log(f"Results exported to {filename}")
                messagebox.showinfo("Success", f"Results exported to {filename}")
                
            except Exception as e:
                self.log(f"Export error: {str(e)}")
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

def main():
    root = tk.Tk()
    app = CTFPwnTool(root)
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    root.mainloop()

if __name__ == "__main__":
    main()

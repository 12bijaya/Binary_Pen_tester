#!/usr/bin/env python3

import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import time
import threading
import struct
import re
import json
import tempfile
import random
import signal
import hashlib
from datetime import datetime
import platform
import sys
from typing import Dict, List, Any, Optional, Tuple, Union
import traceback

class Logger:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}"
        
        if self.log_callback:
            self.log_callback(formatted)
        else:
            print(formatted)

class DependencyChecker:
    @staticmethod
    def check_required_tools():
        required_tools = ['file', 'readelf', 'objdump', 'nm', 'strings']
        optional_tools = ['checksec', 'gdb', 'radare2']
        
        missing_required = []
        missing_optional = []
        
        for tool in required_tools:
            if not DependencyChecker._check_tool(tool):
                missing_required.append(tool)
        
        for tool in optional_tools:
            if not DependencyChecker._check_tool(tool):
                missing_optional.append(tool)
        
        return missing_required, missing_optional
    
    @staticmethod
    def _check_tool(tool_name):
        try:
            if platform.system() == 'Windows':
                subprocess.run(['where', tool_name], capture_output=True, check=True, timeout=2)
            else:
                subprocess.run(['which', tool_name], capture_output=True, check=True, timeout=2)
            return True
        except:
            return False

class PatternGenerator:
    @staticmethod
    def create(length: int) -> str:
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        chars += "abcdefghijklmnopqrstuvwxyz0123456789"
        
        pattern = ""
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
    def create_unique(length: int) -> bytes:
        pattern = b""
        for i in range(0, length, 4):
            value = 0x41414100 + (i // 4) % 256
            pattern += struct.pack('<I', value)
        return pattern[:length]
    
    @staticmethod
    def offset(value: Union[int, str, bytes], pattern_length: int = 10000) -> int:
        if isinstance(value, int):
            if value <= 0xFFFFFFFF:
                search_bytes = struct.pack('<I', value)
            else:
                search_bytes = struct.pack('<Q', value)
        elif isinstance(value, str):
            if value.startswith('0x'):
                hex_str = value[2:]
                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str
                try:
                    search_bytes = bytes.fromhex(hex_str)
                except ValueError:
                    return -1
            else:
                search_bytes = value.encode('latin-1', errors='ignore')
        elif isinstance(value, bytes):
            search_bytes = value
        else:
            return -1
        
        pattern = PatternGenerator.create(pattern_length).encode('latin-1', errors='ignore')
        pattern_unique = PatternGenerator.create_unique(pattern_length)
        
        if search_bytes in pattern:
            return pattern.index(search_bytes)
        if search_bytes in pattern_unique:
            return pattern_unique.index(search_bytes)
        
        if len(search_bytes) == 4:
            search_rev = search_bytes[::-1]
            if search_rev in pattern:
                return pattern.index(search_rev)
            if search_rev in pattern_unique:
                return pattern_unique.index(search_rev)
        
        return -1

class BinaryRunner:
    def __init__(self, binary_path: str):
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if not os.access(binary_path, os.X_OK):
            os.chmod(binary_path, 0o755)
        
        self.binary = binary_path
        self.process = None
        self.timeout = 5
        self.cleanup_processes = []
    
    def _cleanup(self):
        for pid in self.cleanup_processes:
            try:
                if platform.system() == 'Windows':
                    os.kill(pid, signal.SIGTERM)
                else:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
            except:
                pass
        self.cleanup_processes = []
    
    def _create_process(self, **kwargs):
        kwargs.setdefault('stdin', subprocess.PIPE)
        kwargs.setdefault('stdout', subprocess.PIPE)
        kwargs.setdefault('stderr', subprocess.PIPE)
        kwargs.setdefault('text', False)
        
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            preexec_fn = None
        else:
            preexec_fn = os.setsid
            kwargs['preexec_fn'] = preexec_fn
        
        try:
            self.process = subprocess.Popen([self.binary], **kwargs)
            if preexec_fn is None:
                self.cleanup_processes.append(self.process.pid)
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to create process: {e}")
    
    def _kill_process(self):
        if self.process:
            try:
                if platform.system() == 'Windows':
                    self.process.terminate()
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                
                for _ in range(10):
                    if self.process.poll() is not None:
                        break
                    time.sleep(0.1)
                
                if self.process.poll() is None:
                    if platform.system() == 'Windows':
                        self.process.kill()
                    else:
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                
                self.process.wait(timeout=1)
            except:
                pass
            finally:
                self.process = None
    
    def run(self, input_data: Union[str, bytes] = b"", timeout: int = None) -> Dict[str, Any]:
        if timeout is None:
            timeout = self.timeout
        
        try:
            if not self._create_process():
                return {'success': False, 'error': 'Process creation failed'}
            
            if isinstance(input_data, str):
                input_bytes = input_data.encode('utf-8', errors='ignore')
            else:
                input_bytes = input_data
            
            stdout, stderr = self.process.communicate(input=input_bytes, timeout=timeout)
            
            stdout_str = self._decode_output(stdout)
            stderr_str = self._decode_output(stderr)
            
            return {
                'success': True,
                'stdout': stdout_str,
                'stderr': stderr_str,
                'returncode': self.process.returncode,
                'crashed': self._is_crash(self.process.returncode),
                'signal': -self.process.returncode if self.process.returncode < 0 else None
            }
            
        except subprocess.TimeoutExpired:
            self._kill_process()
            return {'success': False, 'timeout': True}
        except Exception as e:
            self._kill_process()
            return {'success': False, 'error': str(e)}
        finally:
            self._cleanup()
    
    def run_interactive(self, inputs: List[Union[str, bytes]], timeout: int = None) -> Dict[str, Any]:
        if timeout is None:
            timeout = self.timeout
        
        try:
            if not self._create_process():
                return {'success': False, 'error': 'Process creation failed'}
            
            output_parts = []
            
            for inp in inputs:
                if isinstance(inp, str):
                    inp_bytes = inp.encode('utf-8', errors='ignore')
                else:
                    inp_bytes = inp
                
                self.process.stdin.write(inp_bytes + b'\n')
                self.process.stdin.flush()
                
                time.sleep(0.1)
                
                while True:
                    try:
                        chunk = self.process.stdout.read1(1024)
                        if chunk:
                            output_parts.append(self._decode_output(chunk))
                        else:
                            break
                    except:
                        break
            
            stdout, stderr = self.process.communicate(timeout=timeout)
            output_parts.append(self._decode_output(stdout))
            output_parts.append(self._decode_output(stderr))
            
            return {
                'success': True,
                'output': ''.join(output_parts),
                'returncode': self.process.returncode,
                'crashed': self._is_crash(self.process.returncode)
            }
            
        except subprocess.TimeoutExpired:
            self._kill_process()
            return {'success': False, 'timeout': True}
        except Exception as e:
            self._kill_process()
            return {'success': False, 'error': str(e)}
        finally:
            self._cleanup()
    
    def _decode_output(self, data: bytes) -> str:
        encodings = ['utf-8', 'latin-1', 'ascii', 'cp1252']
        for encoding in encodings:
            try:
                return data.decode(encoding, errors='ignore')
            except UnicodeDecodeError:
                continue
        return data.decode('utf-8', errors='replace')
    
    def _is_crash(self, returncode: int) -> bool:
        if returncode is None:
            return False
        if platform.system() != 'Windows' and returncode < 0:
            return True
        crash_codes = [-11, -6, -10, -4]
        return returncode in crash_codes or returncode > 128

class BinaryAnalyzer:
    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.logger = Logger()
        self.info = {}
    
    def analyze(self) -> Dict[str, Any]:
        self.info = {
            'basic_info': self._get_basic_info(),
            'architecture': self._get_architecture(),
            'protections': self._get_protections(),
            'sections': self._get_sections(),
            'symbols': self._get_symbols(),
            'imports': self._get_imports(),
            'strings': self._get_strings(),
            'entry_point': self._get_entry_point()
        }
        return self.info
    
    def _run_command(self, cmd: List[str]) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                errors='ignore'
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
    
    def _get_basic_info(self) -> Dict[str, str]:
        result = self._run_command(['file', self.binary])
        if result['success']:
            return {'file_info': result['stdout'].strip()}
        return {'file_info': 'Unknown'}
    
    def _get_architecture(self) -> Dict[str, str]:
        result = self._run_command(['readelf', '-h', self.binary])
        if result['success']:
            output = result['stdout']
            arch_info = {'arch': 'unknown', 'bits': 0, 'endian': 'unknown'}
            
            if 'ELF64' in output:
                arch_info['bits'] = 64
            elif 'ELF32' in output:
                arch_info['bits'] = 32
            
            if 'LSB' in output:
                arch_info['endian'] = 'little'
            elif 'MSB' in output:
                arch_info['endian'] = 'big'
            
            if 'x86-64' in output or '64-bit' in output:
                arch_info['arch'] = 'x64'
            elif '80386' in output or 'Intel 80386' in output:
                arch_info['arch'] = 'x86'
            elif 'ARM' in output:
                arch_info['arch'] = 'ARM' + ('64' if arch_info['bits'] == 64 else '')
            elif 'MIPS' in output:
                arch_info['arch'] = 'MIPS'
            elif 'PowerPC' in output:
                arch_info['arch'] = 'PPC'
            
            return arch_info
        return {'arch': 'unknown', 'bits': 0, 'endian': 'unknown'}
    
    def _get_protections(self) -> Dict[str, str]:
        protections = {
            'NX': 'Unknown',
            'PIE': 'Unknown',
            'Canary': 'Unknown',
            'RELRO': 'Unknown',
            'FORTIFY': 'Unknown'
        }
        
        checksec_cmds = [
            ['checksec', '--file=' + self.binary],
            ['bash', '-c', f'checksec --file="{self.binary}" 2>/dev/null']
        ]
        
        for cmd in checksec_cmds:
            result = self._run_command(cmd)
            if result['success'] and result['stdout'].strip():
                output = result['stdout']
                
                if 'NX enabled' in output:
                    protections['NX'] = 'YES'
                elif 'NX disabled' in output:
                    protections['NX'] = 'NO'
                
                if 'PIE enabled' in output:
                    protections['PIE'] = 'YES'
                elif 'No PIE' in output:
                    protections['PIE'] = 'NO'
                
                if 'Canary found' in output:
                    protections['Canary'] = 'YES'
                elif 'No canary found' in output:
                    protections['Canary'] = 'NO'
                
                if 'Full RELRO' in output:
                    protections['RELRO'] = 'FULL'
                elif 'Partial RELRO' in output:
                    protections['RELRO'] = 'PARTIAL'
                elif 'No RELRO' in output:
                    protections['RELRO'] = 'NO'
                
                if 'Yes' in output and 'FORTIFY' in output:
                    protections['FORTIFY'] = 'YES'
                elif 'No' in output and 'FORTIFY' in output:
                    protections['FORTIFY'] = 'NO'
                
                if all(v != 'Unknown' for v in protections.values()):
                    return protections
        
        self._check_protections_fallback(protections)
        return protections
    
    def _check_protections_fallback(self, protections: Dict[str, str]):
        result = self._run_command(['readelf', '-l', self.binary])
        if result['success']:
            for line in result['stdout'].split('\n'):
                if 'GNU_STACK' in line:
                    protections['NX'] = 'NO' if 'RWE' in line else 'YES'
                    break
        
        result = self._run_command(['readelf', '-h', self.binary])
        if result['success']:
            if 'DYN' in result['stdout']:
                protections['PIE'] = 'YES'
            else:
                protections['PIE'] = 'NO'
        
        result = self._run_command(['readelf', '-s', self.binary])
        if result['success']:
            if '__stack_chk_fail' in result['stdout'] or '__stack_chk_guard' in result['stdout']:
                protections['Canary'] = 'YES'
            else:
                protections['Canary'] = 'NO'
        
        result = self._run_command(['readelf', '-d', self.binary])
        if result['success']:
            if 'BIND_NOW' in result['stdout']:
                protections['RELRO'] = 'FULL'
            elif 'DEBUG' in result['stdout']:
                protections['RELRO'] = 'PARTIAL'
            else:
                protections['RELRO'] = 'NO'
    
    def _get_sections(self) -> List[Dict[str, str]]:
        sections = []
        result = self._run_command(['readelf', '-S', '--wide', self.binary])
        
        if result['success']:
            lines = result['stdout'].split('\n')[3:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 7:
                    sections.append({
                        'name': parts[1].strip('[]'),
                        'type': parts[2],
                        'address': parts[3],
                        'offset': parts[4],
                        'size': parts[5],
                        'flags': parts[6] if len(parts) > 6 else ''
                    })
        
        return sections[:15]
    
    def _get_symbols(self) -> Dict[str, List[Dict[str, str]]]:
        symbols = {'functions': [], 'variables': []}
        
        result = self._run_command(['nm', '-n', '--defined-only', self.binary])
        if result['success']:
            for line in result['stdout'].split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    symbol_type = parts[1]
                    symbol_name = parts[2]
                    
                    if symbol_type in ('T', 't'):
                        symbols['functions'].append({
                            'address': parts[0],
                            'name': symbol_name,
                            'type': 'function'
                        })
                    elif symbol_type in ('D', 'd', 'B', 'b'):
                        symbols['variables'].append({
                            'address': parts[0],
                            'name': symbol_name,
                            'type': 'data'
                        })
        
        if not symbols['functions']:
            result = self._run_command(['objdump', '-t', self.binary])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '.text' in line and 'F' in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            symbols['functions'].append({
                                'address': parts[0],
                                'name': parts[-1],
                                'type': 'function'
                            })
        
        return symbols
    
    def _get_imports(self) -> List[Dict[str, str]]:
        imports = []
        result = self._run_command(['readelf', '-s', self.binary])
        
        if result['success']:
            for line in result['stdout'].split('\n'):
                if 'UND' in line and '@' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        imports.append({
                            'address': parts[1],
                            'type': 'import',
                            'name': parts[7].split('@')[0]
                        })
        
        return imports[:20]
    
    def _get_strings(self) -> List[Dict[str, str]]:
        strings = []
        result = self._run_command(['strings', '-n', '4', self.binary])
        
        if result['success']:
            for s in result['stdout'].split('\n'):
                if s.strip():
                    strings.append({
                        'string': s,
                        'length': len(s),
                        'type': 'ascii' if s.isascii() else 'binary'
                    })
        
        return strings[:50]
    
    def _get_entry_point(self) -> str:
        result = self._run_command(['readelf', '-h', self.binary])
        if result['success']:
            for line in result['stdout'].split('\n'):
                if 'Entry point address:' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        return parts[1].strip()
        return 'unknown'

class VulnerabilityScanner:
    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.runner = BinaryRunner(binary_path)
        self.pattern_gen = PatternGenerator()
        self.results = {
            'buffer_overflow': [],
            'format_string': [],
            'command_injection': [],
            'integer_overflow': [],
            'heap_vulnerabilities': [],
            'info_leaks': []
        }
    
    def scan(self, depth: int = 3) -> Dict[str, Any]:
        self.log("Starting vulnerability scan (depth: {depth})")
        
        self._static_analysis()
        
        if depth >= 1:
            self._dynamic_analysis_basic()
        
        if depth >= 2:
            self._dynamic_analysis_advanced()
        
        if depth >= 3:
            self._interactive_analysis()
        
        return self._summarize_results()
    
    def _static_analysis(self):
        analyzer = BinaryAnalyzer(self.binary)
        info = analyzer.analyze()
        
        dangerous_functions = [
            'strcpy', 'strcat', 'gets', 'scanf', 'printf', 'sprintf',
            'system', 'exec', 'popen', 'malloc', 'free', 'strncpy',
            'memcpy', 'strlen', 'read', 'write', 'open', 'close'
        ]
        
        symbols = info.get('symbols', {}).get('functions', [])
        imports = info.get('imports', [])
        
        for func_list, source in [(symbols, 'internal'), (imports, 'imported')]:
            for func in func_list:
                func_name = func.get('name', '').lower()
                for danger in dangerous_functions:
                    if danger in func_name:
                        self.results['buffer_overflow'].append({
                            'type': 'dangerous_function',
                            'function': func_name,
                            'address': func.get('address', 'unknown'),
                            'source': source,
                            'severity': 'high' if danger in ['strcpy', 'gets', 'system'] else 'medium',
                            'description': f'Found dangerous function: {func_name}'
                        })
        
        protections = info.get('protections', {})
        if protections.get('Canary') == 'NO':
            self.results['buffer_overflow'].append({
                'type': 'no_stack_canary',
                'severity': 'high',
                'description': 'Stack protection (Stack Canary) not enabled'
            })
        
        if protections.get('NX') == 'NO':
            self.results['buffer_overflow'].append({
                'type': 'no_nx',
                'severity': 'medium',
                'description': 'NX protection (Data Execution Prevention) not enabled'
            })
        
        if protections.get('PIE') == 'NO':
            self.results['info_leaks'].append({
                'type': 'no_pie',
                'severity': 'low',
                'description': 'PIE (Address Space Layout Randomization) not enabled'
            })
    
    def _dynamic_analysis_basic(self):
        self._test_buffer_overflow()
        self._test_format_string()
    
    def _test_buffer_overflow(self):
        test_sizes = [50, 100, 200, 500, 1000, 2000]
        
        for size in test_sizes:
            pattern = PatternGenerator.create(size)
            
            result = self.runner.run(pattern)
            if result.get('crashed'):
                offset = PatternGenerator.offset('AAAA')
                
                self.results['buffer_overflow'].append({
                    'type': 'dynamic_overflow',
                    'size': size,
                    'offset': offset,
                    'crashed': True,
                    'signal': result.get('signal'),
                    'severity': 'critical',
                    'description': f'Buffer overflow caused crash, size: {size} bytes'
                })
                break
    
    def _test_format_string(self):
        test_payloads = [
            ("%p " * 20, "Pointer leak test"),
            ("%x " * 30, "Hexadecimal dump test"),
            ("AAAA %p %p %p %p %p", "Simple leak test"),
            ("%s", "String leak test")
        ]
        
        for payload, desc in test_payloads:
            result = self.runner.run(payload)
            if result.get('success'):
                output = result.get('stdout', '')
                
                leak_indicators = ['0x7f', '0x55', '0x41', '41414141']
                if any(indicator in output.lower() for indicator in leak_indicators):
                    self.results['format_string'].append({
                        'type': 'format_leak',
                        'test': desc,
                        'leak_detected': True,
                        'severity': 'medium',
                        'description': f'Format string vulnerability: {desc}'
                    })
                    break
    
    def _dynamic_analysis_advanced(self):
        test_payloads = [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "|| ls",
            "&& ls"
        ]
        
        for payload in test_payloads:
            result = self.runner.run(payload)
            if result.get('success'):
                output = result.get('stdout', '')
                if any(x in output for x in ['bin', 'etc', 'home', 'usr']):
                    self.results['command_injection'].append({
                        'type': 'command_injection',
                        'payload': payload,
                        'severity': 'critical',
                        'description': f'Command injection vulnerability: {payload}'
                    })
                    break
    
    def _interactive_analysis(self):
        test_inputs = ['\n', 'help\n', '?\n', 'menu\n', '1\n', '2\n', '3\n']
        
        for inp in test_inputs:
            result = self.runner.run(inp)
            if result.get('success'):
                output = result.get('stdout', '')
                
                menu_patterns = [
                    r'^\s*(\d+)\.\s+(.+)$',
                    r'^\s*\[\s*(\d+)\s*\]\s+(.+)$',
                    r'^\s*Option\s+(\d+):\s+(.+)$'
                ]
                
                for pattern in menu_patterns:
                    matches = re.findall(pattern, output, re.MULTILINE)
                    if matches:
                        for match in matches:
                            self.results['info_leaks'].append({
                                'type': 'menu_structure',
                                'option': match[0],
                                'description': match[1],
                                'severity': 'info',
                                'description': f'Found menu option: {match[0]}. {match[1]}'
                            })
    
    def _summarize_results(self) -> Dict[str, Any]:
        summary = {
            'total_vulnerabilities': 0,
            'by_type': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'details': self.results
        }
        
        for vuln_type, vulns in self.results.items():
            summary['by_type'][vuln_type] = len(vulns)
            summary['total_vulnerabilities'] += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', 'medium')
                if severity in summary['by_severity']:
                    summary['by_severity'][severity] += 1
        
        return summary
    
    def log(self, message):
        print(f"[VulnerabilityScanner] {message}")

class Fuzzer:
    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.runner = BinaryRunner(binary_path)
        self.crashes = []
        self.hangs = []
        self.unique_crashes = set()
        self.stop_flag = False
    
    def fuzz(self, max_cases: int = 1000) -> Dict[str, Any]:
        test_cases = self._generate_test_cases()
        
        for i, test_case in enumerate(test_cases[:max_cases]):
            if self.stop_flag:
                break
            
            if i % 100 == 0:
                print(f"Tested {i}/{max_cases} test cases...")
            
            result = self.runner.run(test_case, timeout=2)
            
            if result.get('timeout'):
                self.hangs.append({
                    'input': test_case[:100],
                    'length': len(test_case),
                    'test_id': i
                })
            
            if result.get('crashed'):
                crash_hash = self._hash_crash(result)
                if crash_hash not in self.unique_crashes:
                    self.unique_crashes.add(crash_hash)
                    self.crashes.append({
                        'input': test_case[:100],
                        'length': len(test_case),
                        'returncode': result.get('returncode'),
                        'signal': result.get('signal'),
                        'test_id': i
                    })
        
        return {
            'total_tests': min(max_cases, len(test_cases)),
            'crashes': self.crashes,
            'unique_crashes': len(self.unique_crashes),
            'hangs': self.hangs,
            'crash_rate': len(self.crashes) / max(1, min(max_cases, len(test_cases)))
        }
    
    def _generate_test_cases(self) -> List[bytes]:
        test_cases = []
        
        boundaries = [0, 1, -1, 2147483647, -2147483648]
        for b in boundaries:
            test_cases.append(str(b).encode())
        
        strings = [
            b"",
            b"A" * 10,
            b"A" * 100,
            b"A" * 1000,
            b"%p" * 50,
            b"%n" * 20,
            b"%s" * 30,
            b"\x00" * 10,
            b"\xff" * 10,
            b"\n" * 5,
            b"\t" * 10,
            b"../../etc/passwd",
            b";/bin/sh",
            b"`id`",
            b"$(whoami)"
        ]
        test_cases.extend(strings)
        
        for _ in range(500):
            length = random.randint(1, 2000)
            if random.choice([True, False]):
                test_case = bytes(random.getrandbits(8) for _ in range(length))
            else:
                chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%$#@!&*"
                test_case = ''.join(random.choice(chars) for _ in range(length)).encode()
            test_cases.append(test_case)
        
        for length in [100, 500, 1000, 2000]:
            pattern = PatternGenerator.create(length).encode()
            test_cases.append(pattern)
        
        return test_cases
    
    def _hash_crash(self, result: Dict[str, Any]) -> str:
        components = [
            str(result.get('returncode')),
            str(result.get('signal'))
        ]
        return hashlib.md5(''.join(components).encode()).hexdigest()
    
    def stop(self):
        self.stop_flag = True
        if self.runner.process:
            self.runner._kill_process()

class IntelligentFuzzer:
    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.runner = BinaryRunner(binary_path)
        self.pattern_gen = PatternGenerator()
        self.menu_structure = {}
        self.input_points = []
        self.crashes = []
        self.leaks = []
        self.offsets = {}
        self.discovered_options = []
        self.state = "initial"
        self.stop_flag = False
        
    def discover_menu(self, max_depth: int = 3) -> Dict[str, Any]:
        print("[*] Discovering menu structure...")
        
        test_inputs = [
            "", "\n", "help\n", "?\n", "menu\n", "options\n",
            "1\n", "2\n", "3\n", "4\n", "5\n",
            "a\n", "b\n", "c\n", "A\n", "B\n", "C\n"
        ]
        
        for inp in test_inputs:
            if self.stop_flag:
                break
                
            result = self.runner.run(inp)
            if not result.get('success'):
                continue
                
            output = result.get('stdout', '') + result.get('stderr', '')
            self._analyze_output_for_menu(output, inp)
        
        self._explore_options(max_depth)
        
        return {
            'menu_structure': self.menu_structure,
            'input_points': self.input_points,
            'discovered_options': self.discovered_options
        }
    
    def _analyze_output_for_menu(self, output: str, input_sent: str):
        menu_patterns = [
            r'^\s*(\d+)\.\s+(.+)$',
            r'^\s*\[\s*(\d+)\s*\]\s+(.+)$',
            r'^\s*Option\s+(\d+):\s+(.+)$',
            r'^\s*(\w+)\)\s+(.+)$',
            r'^\s*>\s*(.+)$',
            r'^\s*-\s*(.+)$',
        ]
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line or len(line) < 2:
                continue
            
            prompt_indicators = ['Enter', 'Input', 'Choice', 'Select', ':', '>', '$', '#']
            if any(indicator in line for indicator in prompt_indicators):
                self.input_points.append({
                    'prompt': line,
                    'state': self.state,
                    'input_sent': input_sent
                })
            
            for pattern in menu_patterns:
                match = re.match(pattern, line)
                if match:
                    option = match.group(1).strip()
                    description = match.group(2).strip()
                    
                    if option not in self.menu_structure:
                        self.menu_structure[option] = {
                            'description': description,
                            'tested': False,
                            'leads_to_input': False
                        }
                        self.discovered_options.append(option)
    
    def _explore_options(self, max_depth: int):
        print(f"[*] Exploring {len(self.discovered_options)} discovered options...")
        
        for option in self.discovered_options[:10]:
            if self.stop_flag:
                break
            
            print(f"[*] Testing option: {option}")
            result = self.runner.run(f"{option}\n")
            
            if result.get('success'):
                output = result.get('stdout', '')
                self._analyze_output_for_menu(output, option)
                
                prompts_found = [
                    'Enter', 'Input', 'Choice', 'Select', 
                    'name', 'data', 'string', 'value',
                    ':', '>', '?'
                ]
                if any(prompt in output for prompt in prompts_found):
                    self.menu_structure[option]['leads_to_input'] = True
                    self._test_input_point(option, output)
    
    def _test_input_point(self, option: str, context_output: str):
        print(f"[*] Testing input point after option: {option}")
        
        self.runner.run(f"{option}\n")
        
        test_payloads = [
            ("A" * 100, "Long string test"),
            ("%p" * 10, "Format string leak test"),
            ("%n" * 5, "Format string write test"),
            ("\x00" * 50, "Null byte test"),
            ("../../etc/passwd", "Path traversal test"),
            ("'; ls;'", "Command injection test"),
        ]
        
        for payload, desc in test_payloads:
            if self.stop_flag:
                break
                
            result = self.runner.run_interactive([f"{option}\n", f"{payload}\n"])
            
            if result.get('crashed'):
                self._analyze_crash(payload, result, option)
                break
            elif result.get('success'):
                self._analyze_output_for_leaks(result.get('output', ''), payload, option)
    
    def fuzz_menu_option(self, option: str, input_text: str, test_count: int = 500) -> Dict[str, Any]:
        print(f"[*] Fuzzing option '{option}' with input field...")
        
        crashes = []
        leaks = []
        unique_crashes = set()
        
        test_cases = self._generate_smart_test_cases()
        
        for i, test_case in enumerate(test_cases[:test_count]):
            if self.stop_flag:
                break
                
            if i % 50 == 0:
                print(f"[*] Tested {i}/{test_count} cases for option {option}")
            
            inputs = [f"{option}\n", f"{test_case}\n"]
            result = self.runner.run_interactive(inputs)
            
            if result.get('crashed'):
                crash_hash = self._hash_crash(result)
                if crash_hash not in unique_crashes:
                    unique_crashes.add(crash_hash)
                    crash_info = {
                        'option': option,
                        'input': test_case[:100] if isinstance(test_case, str) else str(test_case)[:100],
                        'length': len(test_case) if isinstance(test_case, (str, bytes)) else 0,
                        'returncode': result.get('returncode'),
                        'signal': result.get('signal'),
                        'test_id': i,
                        'offset_info': self._calculate_offset(test_case, result)
                    }
                    crashes.append(crash_info)
            
            elif result.get('success'):
                leak_info = self._detect_leaks(result.get('output', ''), test_case, option)
                if leak_info:
                    leaks.append(leak_info)
        
        return {
            'option': option,
            'total_tests': min(test_count, len(test_cases)),
            'crashes': crashes,
            'leaks': leaks,
            'unique_crashes': len(unique_crashes)
        }
    
    def _generate_smart_test_cases(self) -> List[Union[str, bytes]]:
        test_cases = []
        
        for length in [64, 128, 256, 512, 1024, 2048, 4096]:
            test_cases.append("A" * length)
            test_cases.append(PatternGenerator.create(length))
            test_cases.append(PatternGenerator.create_unique(length))
        
        for i in range(1, 20):
            test_cases.append(f"%{i}$p")
            test_cases.append(f"%{i}$s")
            test_cases.append(f"%{i}$n")
        
        test_cases.extend([
            "%p " * 50,
            "%x " * 50,
            "%s" * 30,
            "%n" * 20,
        ])
        
        test_cases.extend([
            "-1", "0", "2147483647", "2147483648", "-2147483648", "-2147483649",
            "9999999999", "-9999999999", "0xffffffff", "0x100000000"
        ])
        
        injections = [
            "; ls;", "| ls", "`ls`", "$(ls)", "|| ls", "&& ls",
            "; cat /etc/passwd;", "| cat /etc/passwd",
            "'; sh;'", '\"; sh;\"'
        ]
        test_cases.extend(injections)
        
        paths = [
            "../../etc/passwd", "/etc/passwd", "..\\..\\windows\\system32\\config\\SAM",
            "file:///etc/passwd", "\\..\\..\\etc\\passwd"
        ]
        test_cases.extend(paths)
        
        specials = [
            "\x00" * 50,
            "\xff" * 50,
            "\n" * 10,
            "\r\n" * 10,
            "\t" * 20,
        ]
        test_cases.extend(specials)
        
        for _ in range(200):
            length = random.randint(1, 2000)
            if random.choice([True, False]):
                test_case = bytes([random.randint(0, 255) for _ in range(length)])
            else:
                chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/`~"
                test_case = ''.join(random.choice(chars) for _ in range(length))
            test_cases.append(test_case)
        
        return test_cases
    
    def _analyze_crash(self, payload: str, result: Dict[str, Any], context: str = ""):
        print(f"[*] Crash detected! Analyzing...")
        
        crash_info = {
            'context': context,
            'payload': payload[:100],
            'returncode': result.get('returncode'),
            'signal': result.get('signal'),
            'vulnerability_type': 'unknown'
        }
        
        if isinstance(payload, str) and payload.startswith(("A" * 50, "AAAA")):
            offset = self._find_offset_from_crash(payload, result)
            if offset != -1:
                crash_info['offset'] = offset
                crash_info['vulnerability_type'] = 'buffer_overflow'
                print(f"[+] Buffer overflow at offset: {offset}")
        
        elif '%' in str(payload):
            crash_info['vulnerability_type'] = 'format_string'
            if '%n' in str(payload):
                crash_info['subtype'] = 'format_string_write'
            else:
                crash_info['subtype'] = 'format_string_read'
        
        self.crashes.append(crash_info)
        return crash_info
    
    def _find_offset_from_crash(self, payload: str, result: Dict[str, Any]) -> int:
        if isinstance(payload, str) and len(payload) > 100:
            pattern = PatternGenerator.create(len(payload))
            pattern_result = self.runner.run(pattern)
            
            if pattern_result.get('crashed'):
                return len(payload) // 2
        
        return -1
    
    def _analyze_output_for_leaks(self, output: str, payload: str, context: str):
        pointer_pattern = r'(0x[0-9a-fA-F]{8,16})'
        pointers = re.findall(pointer_pattern, output)
        
        if pointers and '%' in str(payload):
            leak_info = {
                'context': context,
                'payload': payload[:100],
                'leaked_pointers': pointers[:5],
                'vulnerability_type': 'format_string',
                'confidence': 'high' if len(pointers) > 3 else 'medium'
            }
            
            if '%p' in str(payload):
                p_count = str(payload).count('%p')
                if p_count > 0:
                    leak_info['estimated_offset'] = 1
            
            self.leaks.append(leak_info)
            print(f"[+] Format string leak detected: {pointers[:3]}...")
        
        stack_pattern = r'(0x7f[0-9a-fA-F]{9,12})'
        heap_pattern = r'(0x55[0-9a-fA-F]{9,12}|0x56[0-9a-fA-F]{9,12})'
        
        stack_leaks = re.findall(stack_pattern, output)
        heap_leaks = re.findall(heap_pattern, output)
        
        if stack_leaks:
            leak_info = {
                'context': context,
                'payload': payload[:100],
                'leaked_addresses': stack_leaks[:3],
                'type': 'stack_leak',
                'confidence': 'high'
            }
            self.leaks.append(leak_info)
        
        if heap_leaks:
            leak_info = {
                'context': context,
                'payload': payload[:100],
                'leaked_addresses': heap_leaks[:3],
                'type': 'heap_leak',
                'confidence': 'medium'
            }
            self.leaks.append(leak_info)
    
    def _detect_leaks(self, output: str, payload: str, context: str) -> Optional[Dict[str, Any]]:
        leak_indicators = {
            'stack': ['0x7f', '0x7e', '0x7d'],
            'heap': ['0x55', '0x56', '0x57'],
            'libc': ['0x7f', '0x00007f'],
            'pie': ['0x55', '0x000055']
        }
        
        for leak_type, indicators in leak_indicators.items():
            for indicator in indicators:
                if indicator in output.lower():
                    return {
                        'type': f'{leak_type}_leak',
                        'context': context,
                        'payload': str(payload)[:50],
                        'indicator': indicator,
                        'output_snippet': output[:200]
                    }
        
        return None
    
    def _hash_crash(self, result: Dict[str, Any]) -> str:
        components = [
            str(result.get('returncode')),
            str(result.get('signal')),
            result.get('stdout', '')[:50],
            result.get('stderr', '')[:50]
        ]
        return hashlib.md5(''.join(components).encode()).hexdigest()
    
    def _calculate_offset(self, payload, result: Dict[str, Any]) -> Dict[str, Any]:
        offset_info = {
            'found': False,
            'offset': -1,
            'method': 'unknown'
        }
        
        if isinstance(payload, str) and any(pattern in payload for pattern in ['AAA', 'Aa0', 'Aa1']):
            if result.get('signal') == -11:
                offset_info['method'] = 'pattern_analysis'
                offset_info['offset'] = len(payload) // 2
                offset_info['confidence'] = 'low'
        
        return offset_info
    
    def calculate_format_string_offset(self, option: str) -> Dict[str, Any]:
        print(f"[*] Calculating format string offset for option: {option}")
        
        results = []
        
        for position in range(1, 21):
            payload = f"%{position}$p"
            result = self.runner.run_interactive([f"{option}\n", f"{payload}\n"])
            
            if result.get('success'):
                output = result.get('output', '')
                
                if '0x' in output and 'nil' not in output.lower():
                    match = re.search(r'(0x[0-9a-fA-F]{8,16})', output)
                    if match:
                        pointer = match.group(1)
                        results.append({
                            'position': position,
                            'pointer': pointer,
                            'controlled': True,
                            'note': 'You control this argument'
                        })
                    else:
                        results.append({
                            'position': position,
                            'pointer': 'unknown',
                            'controlled': False
                        })
                else:
                    results.append({
                        'position': position,
                        'pointer': None,
                        'controlled': False
                    })
        
        controlled_positions = [r for r in results if r.get('controlled')]
        
        return {
            'option': option,
            'tested_positions': 20,
            'controlled_positions': [r['position'] for r in controlled_positions],
            'detailed_results': results,
            'recommendation': f"Use positions {[r['position'] for r in controlled_positions[:3]]} for exploitation"
        }
    
    def calculate_buffer_offset(self, option: str) -> Dict[str, Any]:
        print(f"[*] Calculating buffer offset for option: {option}")
        
        test_sizes = [100, 200, 300, 400, 500]
        results = []
        
        for size in test_sizes:
            pattern = PatternGenerator.create(size)
            
            result = self.runner.run_interactive([f"{option}\n", f"{pattern}\n"])
            
            if result.get('crashed'):
                results.append({
                    'size': size,
                    'crashed': True,
                    'signal': result.get('signal'),
                    'estimated_offset': size - 8
                })
                
                exact_offset = self._binary_search_offset(option, size)
                if exact_offset != -1:
                    return {
                        'option': option,
                        'exact_offset': exact_offset,
                        'method': 'binary_search',
                        'confidence': 'high'
                    }
            else:
                results.append({
                    'size': size,
                    'crashed': False
                })
        
        return {
            'option': option,
            'results': results,
            'estimated_offset': self._estimate_from_results(results),
            'method': 'pattern_fuzzing',
            'confidence': 'medium'
        }
    
    def _binary_search_offset(self, option: str, crash_size: int) -> int:
        low = crash_size - 100
        high = crash_size
        last_crash = crash_size
        
        for _ in range(10):
            if high - low <= 1:
                return last_crash
            
            mid = (low + high) // 2
            pattern = PatternGenerator.create(mid)
            
            result = self.runner.run_interactive([f"{option}\n", f"{pattern}\n"])
            
            if result.get('crashed'):
                last_crash = mid
                high = mid
            else:
                low = mid
        
        return last_crash
    
    def _estimate_from_results(self, results: List[Dict]) -> int:
        crashes = [r for r in results if r.get('crashed')]
        if not crashes:
            return -1
        
        min_crash = min(crashes, key=lambda x: x['size'])
        return min_crash['size'] - 8
    
    def run_comprehensive_fuzzing(self, max_options: int = 5, tests_per_option: int = 300) -> Dict[str, Any]:
        print("[*] Starting comprehensive fuzzing...")
        
        discovery_results = self.discover_menu()
        
        fuzzing_results = []
        
        for option in discovery_results['discovered_options'][:max_options]:
            if self.stop_flag:
                break
                
            print(f"[*] Fuzzing option: {option}")
            result = self.fuzz_menu_option(option, "", tests_per_option)
            fuzzing_results.append(result)
            
            if result.get('crashes'):
                print(f"[*] Crashes found for option {option}, calculating offsets...")
                
                offset_result = self.calculate_buffer_offset(option)
                self.offsets[option] = offset_result
                
                if result.get('leaks'):
                    fmt_result = self.calculate_format_string_offset(option)
                    self.offsets[f"{option}_format"] = fmt_result
        
        return {
            'discovery': discovery_results,
            'fuzzing': fuzzing_results,
            'offsets': self.offsets,
            'total_crashes': sum(len(r.get('crashes', [])) for r in fuzzing_results),
            'total_leaks': sum(len(r.get('leaks', [])) for r in fuzzing_results)
        }
    
    def stop(self):
        self.stop_flag = True
        if self.runner.process:
            self.runner._kill_process()

class ExploitGenerator:
    @staticmethod
    def generate_buffer_overflow(offset: int, arch: str = 'x64') -> str:
        if arch == 'x64':
            return ExploitGenerator._generate_x64_overflow(offset)
        else:
            return ExploitGenerator._generate_x86_overflow(offset)
    
    @staticmethod
    def _generate_x64_overflow(offset: int) -> str:
        return f'''#!/usr/bin/env python3
import struct
import subprocess
import sys

binary = "./target"
offset = {offset}

def create_payload():
    payload = b"A" * offset
    payload += struct.pack("<Q", 0xdeadbeefcafebabe)
    return payload

def main():
    payload = create_payload()
    print(f"[*] Payload length: {{len(payload)}}")
    print(f"[*] Sending payload...")
    
    try:
        p = subprocess.Popen([binary], stdin=subprocess.PIPE)
        p.communicate(input=payload, timeout=5)
    except Exception as e:
        print(f"[-] Error: {{e}}")

if __name__ == "__main__":
    main()'''
    
    @staticmethod
    def _generate_x86_overflow(offset: int) -> str:
        return f'''#!/usr/bin/env python3
import struct
import subprocess
import sys

binary = "./target"
offset = {offset}

def create_payload():
    payload = b"A" * offset
    payload += struct.pack("<I", 0xdeadbeef)
    return payload

def main():
    payload = create_payload()
    print(f"[*] Payload length: {{len(payload)}}")
    print(f"[*] Sending payload...")
    
    try:
        p = subprocess.Popen([binary], stdin=subprocess.PIPE)
        p.communicate(input=payload, timeout=5)
    except Exception as e:
        print(f"[-] Error: {{e}}")

if __name__ == "__main__":
    main()'''
    
    @staticmethod
    def generate_format_string(offset: int) -> str:
        return f'''#!/usr/bin/env python3
import struct
import subprocess
import sys

binary = "./target"

def leak_memory():
    print("[*] Leaking memory addresses...")
    
    for i in range(1, 50):
        payload = f"%{{i}}$p".encode()
        
        p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = p.communicate(input=payload, timeout=3)
        
        if b'0x' in stdout and b'(nil)' not in stdout:
            print(f"[+] Offset {{i}}: {{stdout.strip().decode()}}")

def main():
    print("[*] Format string exploit template")
    print("[*] You need to adjust offsets and addresses")
    
    print("[*] Exploit template generated. Modify as needed.")

if __name__ == "__main__":
    main()'''
    
    @staticmethod
    def generate_rop_chain(arch: str = 'x64') -> str:
        if arch == 'x64':
            return ExploitGenerator._generate_x64_rop()
        else:
            return ExploitGenerator._generate_x86_rop()
    
    @staticmethod
    def _generate_x64_rop() -> str:
        return '''#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

def create_rop_chain():
    rop = ROP(exe)
    return rop.chain()

def main():
    global exe
    
    exe = ELF('./target')
    
    rop_chain = create_rop_chain()
    print(rop.dump())
    
    offset = 72
    payload = fit({
        offset: rop_chain
    })
    
    print(f"[*] Payload length: {len(payload)}")
    print("[*] Send payload manually or modify to send automatically")

if __name__ == "__main__":
    main()'''
    
    @staticmethod
    def _generate_x86_rop() -> str:
        return '''#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

def create_rop_chain():
    rop = ROP(exe)
    return rop.chain()

def main():
    global exe
    
    exe = ELF('./target')
    
    rop_chain = create_rop_chain()
    print(rop.dump())
    
    offset = 44
    payload = fit({
        offset: rop_chain
    })
    
    print(f"[*] Payload length: {len(payload)}")

if __name__ == "__main__":
    main()'''

class CTFPwnToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CTF PWN Tool - Advanced Version")
        self.root.geometry("1400x900")
        self.binary_path = ""
        self.current_results = None
        self.analyzer = None
        self.scanner = None
        self.fuzzer = None
        self.is_running = False
        self._create_gui()
        self._center_window()
        self._check_dependencies()
    
    def _check_dependencies(self):
        missing_required, missing_optional = DependencyChecker.check_required_tools()
        
        if missing_required:
            messagebox.showerror(
                "Missing Dependencies",
                f"Missing required tools: {', '.join(missing_required)}\n\n"
                "Please install: sudo apt-get install binutils file"
            )
            self.root.quit()
        
        if missing_optional:
            self.log(f"Optional tools not installed: {', '.join(missing_optional)}")
    
    def _create_gui(self):
        main_container = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        left_panel = tk.Frame(main_container, width=250, bg='#2c3e50')
        main_container.add(left_panel)
        
        right_panel = tk.Frame(main_container)
        main_container.add(right_panel)
        
        self._create_left_panel(left_panel)
        self._create_notebook(right_panel)
        self._create_status_bar()
    
    def _create_left_panel(self, parent):
        title_frame = tk.Frame(parent, bg='#34495e', height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title = tk.Label(
            title_frame,
            text="⚔️ CTF PWN Tool",
            font=('Arial', 16, 'bold'),
            bg='#34495e',
            fg='white'
        )
        title.pack(expand=True)
        
        info_frame = tk.LabelFrame(parent, text="📁 Binary File", font=('Arial', 10), bg='#2c3e50', fg='white')
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.binary_label = tk.Label(
            info_frame,
            text="No file selected",
            wraplength=230,
            bg='#2c3e50',
            fg='#ecf0f1',
            font=('Arial', 9)
        )
        self.binary_label.pack(padx=10, pady=10)
        
        btn_frame = tk.Frame(parent, bg='#2c3e50')
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        buttons = [
            ("📁 Load Binary File", self.load_binary),
            ("🔍 Analyze Binary", self.analyze_binary),
            ("🛡️ Vulnerability Scan", self.scan_vulnerabilities),
            ("🎯 Fuzzing", self.start_fuzzing),
            ("⚡ Interactive Analysis", self.interactive_analysis),
            ("📊 Offset Calculation", self.calculate_offset),
            ("💣 Generate Exploit", self.generate_exploit),
            ("📈 View Statistics", self.show_statistics),
            ("💾 Export Results", self.export_results),
            ("❌ Exit", self.root.quit)
        ]
        
        for text, command in buttons:
            btn = tk.Button(
                btn_frame,
                text=text,
                command=command,
                bg='#3498db',
                fg='white',
                font=('Arial', 10),
                width=25,
                anchor='w',
                padx=10
            )
            btn.pack(pady=3)
        
        status_frame = tk.LabelFrame(parent, text="📊 Current Status", font=('Arial', 10), bg='#2c3e50', fg='white')
        status_frame.pack(fill=tk.X, padx=10, pady=10, side=tk.BOTTOM)
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg='#2c3e50',
            fg='#2ecc71',
            font=('Arial', 9)
        )
        self.status_label.pack(padx=10, pady=5)
    
    def _create_notebook(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self._create_analysis_tab()
        self._create_vulnerabilities_tab()
        self._create_fuzzing_tab()
        self._create_interactive_tab()
        self._create_exploit_tab()
        self._create_log_tab()
    
    def _create_analysis_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="🔍 Analysis")
        
        toolbar = tk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(
            toolbar,
            text="Re-analyze",
            command=self.analyze_binary,
            bg='#3498db',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            toolbar,
            text="Export Analysis",
            command=lambda: self.export_text(self.analysis_text),
            bg='#2ecc71',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        self.analysis_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.analysis_text.config(state='disabled')
    
    def _create_vulnerabilities_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="🛡️ Vulnerabilities")
        
        paned = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(paned)
        paned.add(left_frame, width=300)
        
        tk.Label(
            left_frame,
            text="Discovered Vulnerabilities",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w', padx=10, pady=10)
        
        self.vuln_listbox = tk.Listbox(
            left_frame,
            font=('Consolas', 10),
            selectmode=tk.SINGLE
        )
        self.vuln_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.vuln_listbox.bind('<<ListboxSelect>>', self.on_vuln_select)
        
        right_frame = tk.Frame(paned)
        paned.add(right_frame)
        
        tk.Label(
            right_frame,
            text="Vulnerability Details",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w', padx=10, pady=10)
        
        self.vuln_details = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.vuln_details.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.vuln_details.config(state='disabled')
    
    def _create_fuzzing_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="🎯 Fuzzing")
        
        control_notebook = ttk.Notebook(frame)
        control_notebook.pack(fill=tk.X, padx=10, pady=5)
        
        basic_frame = tk.Frame(control_notebook)
        control_notebook.add(basic_frame, text="Basic")
        
        tk.Label(basic_frame, text="Test Case Count:").pack(side=tk.LEFT, padx=5)
        self.fuzz_count = tk.IntVar(value=1000)
        tk.Spinbox(
            basic_frame,
            from_=100,
            to=10000,
            increment=100,
            textvariable=self.fuzz_count,
            width=10
        ).pack(side=tk.LEFT, padx=5)
        
        self.start_fuzz_btn = tk.Button(
            basic_frame,
            text="Start Basic Fuzzing",
            command=self.start_fuzzing,
            bg='#3498db',
            fg='white'
        )
        self.start_fuzz_btn.pack(side=tk.LEFT, padx=10)
        
        intel_frame = tk.Frame(control_notebook)
        control_notebook.add(intel_frame, text="Intelligent")
        
        tk.Label(intel_frame, text="Options to test:").pack(side=tk.LEFT, padx=5)
        self.intel_options = tk.IntVar(value=5)
        tk.Spinbox(
            intel_frame,
            from_=1,
            to=20,
            textvariable=self.intel_options,
            width=5
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Label(intel_frame, text="Tests per option:").pack(side=tk.LEFT, padx=5)
        self.tests_per_option = tk.IntVar(value=200)
        tk.Spinbox(
            intel_frame,
            from_=50,
            to=1000,
            textvariable=self.tests_per_option,
            width=5
        ).pack(side=tk.LEFT, padx=5)
        
        self.start_intel_fuzz_btn = tk.Button(
            intel_frame,
            text="Start Intelligent Fuzzing",
            command=self.start_intelligent_fuzzing,
            bg='#e74c3c',
            fg='white'
        )
        self.start_intel_fuzz_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_fuzz_btn = tk.Button(
            frame,
            text="Stop Fuzzing",
            command=self.stop_fuzzing,
            bg='#95a5a6',
            fg='white',
            state='disabled'
        )
        self.stop_fuzz_btn.pack(pady=5)
        
        self.fuzz_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.fuzz_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.fuzz_text.config(state='disabled')
    
    def _create_interactive_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="⚡ Interactive")
        
        control_frame = tk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(
            control_frame,
            text="Start Interactive Analysis",
            command=self.interactive_analysis,
            bg='#9b59b6',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        self.interactive_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.interactive_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _create_exploit_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="💣 Exploit")
        
        control_frame = tk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_frame, text="Exploit Type:").pack(side=tk.LEFT, padx=5)
        self.exploit_type = tk.StringVar(value="buffer_overflow")
        
        exploit_types = [
            ("Buffer Overflow", "buffer_overflow"),
            ("Format String", "format_string"),
            ("ROP Chain", "rop"),
            ("Command Injection", "command_injection")
        ]
        
        for text, value in exploit_types:
            tk.Radiobutton(
                control_frame,
                text=text,
                variable=self.exploit_type,
                value=value
            ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            control_frame,
            text="Generate Exploit",
            command=self.generate_exploit,
            bg='#e67e22',
            fg='white'
        ).pack(side=tk.LEFT, padx=10)
        
        self.exploit_editor = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.exploit_editor.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _create_log_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="📋 Log")
        
        toolbar = tk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(
            toolbar,
            text="Clear Log",
            command=self.clear_log,
            bg='#95a5a6',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            toolbar,
            text="Export Log",
            command=lambda: self.export_text(self.log_text),
            bg='#2ecc71',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        self.log_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text.config(state='disabled')
    
    def _create_status_bar(self):
        status_bar = tk.Frame(self.root, height=25, bg='#2c3e50')
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        
        self.status_message = tk.Label(
            status_bar,
            text="Ready",
            bg='#2c3e50',
            fg='white',
            font=('Arial', 9)
        )
        self.status_message.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(
            status_bar,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side=tk.RIGHT, padx=10, pady=2)
    
    def _center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def log(self, message):
        def update_log():
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state='disabled')
        
        if threading.current_thread() is threading.main_thread():
            update_log()
        else:
            self.root.after(0, update_log)
    
    def update_status(self, message, is_working=False):
        def update():
            self.status_message.config(text=message)
            if is_working:
                self.progress.start()
            else:
                self.progress.stop()
        
        if threading.current_thread() is threading.main_thread():
            update()
        else:
            self.root.after(0, update)
    
    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
    
    def load_binary(self):
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[
                ("Executable files", "*.elf *.exe *.bin *.out"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            self.binary_path = filename
            self.binary_label.config(text=os.path.basename(filename))
            self.log(f"Loaded binary file: {filename}")
            self.update_status(f"Loaded: {os.path.basename(filename)}")
    
    def analyze_binary(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        def analyze_thread():
            self.is_running = True
            self.update_status("Analyzing binary file...", True)
            
            try:
                self.analyzer = BinaryAnalyzer(self.binary_path)
                results = self.analyzer.analyze()
                
                self.root.after(0, self.display_analysis, results)
                self.root.after(0, self.log, "Binary analysis completed!")
                
            except Exception as e:
                self.root.after(0, self.log, f"Analysis failed: {str(e)}")
                self.root.after(0, traceback.print_exc)
            
            finally:
                self.root.after(0, lambda: self.update_status("Ready", False))
                self.is_running = False
        
        if not self.is_running:
            threading.Thread(target=analyze_thread, daemon=True).start()
    
    def display_analysis(self, results):
        self.analysis_text.config(state='normal')
        self.analysis_text.delete(1.0, tk.END)
        
        text = "=" * 60 + "\n"
        text += "                   Binary Analysis Report\n"
        text += "=" * 60 + "\n\n"
        
        text += "📁 Basic Information\n"
        text += "-" * 40 + "\n"
        if 'basic_info' in results:
            text += f"{results['basic_info'].get('file_info', 'Unknown')}\n"
        
        if 'architecture' in results:
            arch = results['architecture']
            text += f"\n🏗️ Architecture: {arch.get('arch', 'Unknown')} ({arch.get('bits', 0)}-bit)\n"
            text += f"Endianness: {arch.get('endian', 'Unknown')}\n"
        
        if 'protections' in results:
            text += "\n🛡️ Security Protections\n"
            text += "-" * 40 + "\n"
            for prot, value in results['protections'].items():
                icon = "✅" if value == 'YES' else "❌" if value == 'NO' else "❓"
                text += f"{prot}: {value} {icon}\n"
        
        if 'sections' in results:
            text += "\n📊 Section Information\n"
            text += "-" * 40 + "\n"
            for sec in results['sections'][:10]:
                text += f"{sec['name']:20} {sec['address']:>10} {sec['size']:>10}\n"
        
        if 'symbols' in results:
            symbols = results['symbols']
            if symbols.get('functions'):
                text += "\n🔧 Function Information\n"
                text += "-" * 40 + "\n"
                for func in symbols['functions'][:15]:
                    text += f"{func['address']:>10} {func['name']}\n"
        
        self.analysis_text.insert(tk.END, text)
        self.analysis_text.config(state='disabled')
    
    def scan_vulnerabilities(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        def scan_thread():
            self.is_running = True
            self.update_status("Scanning for vulnerabilities...", True)
            
            try:
                self.scanner = VulnerabilityScanner(self.binary_path)
                results = self.scanner.scan(depth=2)
                
                self.current_results = results
                
                self.root.after(0, self.display_vulnerabilities, results)
                self.root.after(0, self.log, "Vulnerability scan completed!")
                
            except Exception as e:
                self.root.after(0, self.log, f"Scan failed: {str(e)}")
            
            finally:
                self.root.after(0, lambda: self.update_status("Ready", False))
                self.is_running = False
        
        if not self.is_running:
            threading.Thread(target=scan_thread, daemon=True).start()
    
    def display_vulnerabilities(self, results):
        self.vuln_listbox.delete(0, tk.END)
        
        details = results.get('details', {})
        
        for vuln_type, vulns in details.items():
            if vulns:
                self.vuln_listbox.insert(tk.END, f"--- {vuln_type.upper()} ---")
                for vuln in vulns[:10]:
                    desc = vuln.get('description', 'Unknown vulnerability')
                    severity = vuln.get('severity', 'Unknown')
                    self.vuln_listbox.insert(tk.END, f"  [{severity}] {desc[:50]}")
        
        self.vuln_details.config(state='normal')
        self.vuln_details.delete(1.0, tk.END)
        
        text = "=" * 60 + "\n"
        text += "                   Vulnerability Scan Report\n"
        text += "=" * 60 + "\n\n"
        
        text += f"📈 Total Vulnerabilities: {results.get('total_vulnerabilities', 0)}\n\n"
        
        text += "Statistics by Type:\n"
        text += "-" * 40 + "\n"
        for vuln_type, count in results.get('by_type', {}).items():
            text += f"{vuln_type}: {count}\n"
        
        text += "\nStatistics by Severity:\n"
        text += "-" * 40 + "\n"
        for severity, count in results.get('by_severity', {}).items():
            text += f"{severity}: {count}\n"
        
        self.vuln_details.insert(tk.END, text)
        self.vuln_details.config(state='disabled')
    
    def on_vuln_select(self, event):
        selection = self.vuln_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        selected = self.vuln_listbox.get(index)
    
    def start_fuzzing(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        def fuzz_thread():
            self.is_running = True
            self.update_status("Fuzzing in progress...", True)
            self.root.after(0, self.start_fuzz_btn.config, {'state': 'disabled'})
            self.root.after(0, self.start_intel_fuzz_btn.config, {'state': 'disabled'})
            self.root.after(0, self.stop_fuzz_btn.config, {'state': 'normal'})
            
            try:
                self.fuzzer = Fuzzer(self.binary_path)
                max_cases = self.fuzz_count.get()
                results = self.fuzzer.fuzz(max_cases)
                
                self.root.after(0, self.display_fuzzing_results, results)
                self.root.after(0, self.log, f"Fuzzing completed! Found {len(results['crashes'])} crashes")
                
            except Exception as e:
                self.root.after(0, self.log, f"Fuzzing failed: {str(e)}")
            
            finally:
                self.root.after(0, lambda: self.update_status("Ready", False))
                self.root.after(0, self.start_fuzz_btn.config, {'state': 'normal'})
                self.root.after(0, self.start_intel_fuzz_btn.config, {'state': 'normal'})
                self.root.after(0, self.stop_fuzz_btn.config, {'state': 'disabled'})
                self.is_running = False
        
        if not self.is_running:
            threading.Thread(target=fuzz_thread, daemon=True).start()
    
    def start_intelligent_fuzzing(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        def fuzz_thread():
            self.is_running = True
            self.update_status("Starting intelligent fuzzing...", True)
            self.root.after(0, self.start_fuzz_btn.config, {'state': 'disabled'})
            self.root.after(0, self.start_intel_fuzz_btn.config, {'state': 'disabled'})
            self.root.after(0, self.stop_fuzz_btn.config, {'state': 'normal'})
            
            try:
                self.intelligent_fuzzer = IntelligentFuzzer(self.binary_path)
                
                results = self.intelligent_fuzzer.run_comprehensive_fuzzing(
                    max_options=self.intel_options.get(),
                    tests_per_option=self.tests_per_option.get()
                )
                
                self.root.after(0, self.display_intelligent_fuzzing_results, results)
                self.root.after(0, self.log, f"Intelligent fuzzing completed! Found {results['total_crashes']} crashes")
                
            except Exception as e:
                self.root.after(0, self.log, f"Fuzzing failed: {str(e)}")
                traceback.print_exc()
            
            finally:
                self.root.after(0, lambda: self.update_status("Ready", False))
                self.root.after(0, self.start_fuzz_btn.config, {'state': 'normal'})
                self.root.after(0, self.start_intel_fuzz_btn.config, {'state': 'normal'})
                self.root.after(0, self.stop_fuzz_btn.config, {'state': 'disabled'})
                self.is_running = False
        
        if not self.is_running:
            threading.Thread(target=fuzz_thread, daemon=True).start()
    
    def display_fuzzing_results(self, results):
        self.fuzz_text.config(state='normal')
        self.fuzz_text.delete(1.0, tk.END)
        
        text = "=" * 60 + "\n"
        text += "                   Fuzzing Report\n"
        text += "=" * 60 + "\n\n"
        
        text += f"📊 Total Test Cases: {results['total_tests']}\n"
        text += f"💥 Crashes Found: {len(results['crashes'])}\n"
        text += f"🔄 Unique Crashes: {results['unique_crashes']}\n"
        text += f"⏰ Timeouts: {len(results['hangs'])}\n"
        text += f"📈 Crash Rate: {results['crash_rate']:.2%}\n\n"
        
        if results['crashes']:
            text += "Crash Details:\n"
            text += "-" * 40 + "\n"
            for i, crash in enumerate(results['crashes'][:10], 1):
                text += f"{i}. Input: {crash['input']}\n"
                text += f"   Length: {crash['length']}\n"
                text += f"   Signal: {crash.get('signal', 'Unknown')}\n"
                text += f"   Test ID: {crash['test_id']}\n\n"
        
        self.fuzz_text.insert(tk.END, text)
        self.fuzz_text.config(state='disabled')
    
    def display_intelligent_fuzzing_results(self, results):
        self.fuzz_text.config(state='normal')
        self.fuzz_text.delete(1.0, tk.END)
        
        text = "=" * 60 + "\n"
        text += "              INTELLIGENT FUZZING REPORT\n"
        text += "=" * 60 + "\n\n"
        
        text += "📋 MENU DISCOVERY\n"
        text += "-" * 40 + "\n"
        discovery = results.get('discovery', {})
        text += f"Options discovered: {len(discovery.get('discovered_options', []))}\n"
        text += f"Input points found: {len(discovery.get('input_points', []))}\n\n"
        
        for option in discovery.get('discovered_options', [])[:10]:
            text += f"  • {option}: {discovery.get('menu_structure', {}).get(option, {}).get('description', 'No description')}\n"
        
        text += "\n🎯 FUZZING RESULTS\n"
        text += "-" * 40 + "\n"
        text += f"Total crashes: {results.get('total_crashes', 0)}\n"
        text += f"Total leaks: {results.get('total_leaks', 0)}\n\n"
        
        fuzzing = results.get('fuzzing', [])
        for fuzz_result in fuzzing:
            option = fuzz_result.get('option', 'unknown')
            crashes = len(fuzz_result.get('crashes', []))
            leaks = len(fuzz_result.get('leaks', []))
            
            if crashes > 0 or leaks > 0:
                text += f"  • {option}: {crashes} crashes, {leaks} leaks\n"
                
                if fuzz_result.get('crashes'):
                    crash = fuzz_result['crashes'][0]
                    text += f"    First crash at test #{crash.get('test_id')}, signal: {crash.get('signal')}\n"
        
        text += "\n📏 OFFSET CALCULATIONS\n"
        text += "-" * 40 + "\n"
        offsets = results.get('offsets', {})
        
        for key, offset_info in offsets.items():
            if 'estimated_offset' in offset_info:
                text += f"  • {key}: Offset ~{offset_info['estimated_offset']} (confidence: {offset_info.get('confidence', 'unknown')})\n"
            elif 'exact_offset' in offset_info:
                text += f"  • {key}: Exact offset {offset_info['exact_offset']}\n"
            elif 'controlled_positions' in offset_info:
                positions = offset_info['controlled_positions']
                if positions:
                    text += f"  • {key}: Format string positions {positions} are controlled\n"
        
        text += "\n💥 CRASH DETAILS\n"
        text += "-" * 40 + "\n"
        
        crash_count = 0
        for fuzz_result in fuzzing:
            for crash in fuzz_result.get('crashes', [])[:3]:
                crash_count += 1
                text += f"\nCrash #{crash_count}:\n"
                text += f"  Option: {crash.get('option')}\n"
                text += f"  Input: {crash.get('input', '')[:50]}...\n"
                text += f"  Signal: {crash.get('signal')}\n"
                
                offset_info = crash.get('offset_info', {})
                if offset_info.get('found'):
                    text += f"  Estimated offset: {offset_info.get('offset')}\n"
        
        if crash_count == 0:
            text += "No crashes found.\n"
        
        text += "\n💡 RECOMMENDATIONS\n"
        text += "-" * 40 + "\n"
        
        if results.get('total_crashes', 0) > 0:
            text += "1. Check crash details for buffer overflow patterns\n"
            text += "2. Use offset calculations for exploit development\n"
            text += "3. Test format string positions if leaks were found\n"
        else:
            text += "No vulnerabilities found with current fuzzing.\n"
            text += "Try increasing test count or exploring more options.\n"
        
        self.fuzz_text.insert(tk.END, text)
        self.fuzz_text.config(state='disabled')
    
    def interactive_analysis(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        self.interactive_text.delete(1.0, tk.END)
        self.interactive_text.insert(tk.END, "Interactive Analysis Mode\n")
        self.interactive_text.insert(tk.END, "Type 'quit' to exit\n")
        self.interactive_text.insert(tk.END, "=" * 50 + "\n\n")
        
        self.log("Starting interactive analysis")
    
    def calculate_offset(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Offset Calculation")
        dialog.geometry("400x300")
        
        tk.Label(dialog, text="Value to find:").pack(pady=10)
        value_entry = tk.Entry(dialog, width=40)
        value_entry.pack(pady=5)
        value_entry.insert(0, "0x41414141")
        
        def calculate():
            value_str = value_entry.get()
            offset = PatternGenerator.offset(value_str)
            
            result_text = scrolledtext.ScrolledText(dialog, height=10)
            result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            if offset != -1:
                result_text.insert(tk.END, f"Offset: {offset}\n")
                result_text.insert(tk.END, f"Hexadecimal: 0x{offset:x}\n")
            else:
                result_text.insert(tk.END, "Offset not found\n")
        
        tk.Button(dialog, text="Calculate", command=calculate, bg='#3498db', fg='white').pack(pady=10)
    
    def generate_exploit(self):
        exploit_type = self.exploit_type.get()
        
        arch = 'x64'
        if self.analyzer and self.analyzer.info:
            arch_info = self.analyzer.info.get('architecture', {})
            arch = arch_info.get('arch', 'x64')
            if arch not in ['x64', 'x86']:
                arch = 'x64'
        
        if exploit_type == "buffer_overflow":
            exploit = ExploitGenerator.generate_buffer_overflow(100, arch)
        elif exploit_type == "format_string":
            exploit = ExploitGenerator.generate_format_string(5)
        elif exploit_type == "rop":
            exploit = ExploitGenerator.generate_rop_chain(arch)
        elif exploit_type == "command_injection":
            exploit = """#!/usr/bin/env python3
print("Command injection exploit code")
print("Needs modification based on actual situation")"""
        else:
            exploit = "# Unknown exploit type"
        
        self.exploit_editor.delete(1.0, tk.END)
        self.exploit_editor.insert(tk.END, exploit)
        
        self.log(f"Generated {exploit_type} exploit code")
    
    def show_statistics(self):
        if not self.current_results:
            messagebox.showinfo("Information", "No analysis results available yet")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Statistics")
        dialog.geometry("500x400")
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats = self.current_results
        
        output = "=" * 50 + "\n"
        output += "                   Statistics\n"
        output += "=" * 50 + "\n\n"
        
        output += f"📊 Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}\n\n"
        
        output += "By Vulnerability Type:\n"
        output += "-" * 40 + "\n"
        for vuln_type, count in stats.get('by_type', {}).items():
            output += f"{vuln_type.replace('_', ' ').title()}: {count}\n"
        
        output += "\nBy Severity:\n"
        output += "-" * 40 + "\n"
        for severity, count in stats.get('by_severity', {}).items():
            output += f"{severity.upper()}: {count}\n"
        
        text.insert(tk.END, output)
        text.config(state='disabled')
    
    def export_results(self):
        if not self.current_results and not self.analyzer:
            messagebox.showwarning("Warning", "No results to export")
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
                    'vulnerabilities': self.current_results if self.current_results else {}
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                self.log(f"Results exported to: {filename}")
                messagebox.showinfo("Success", f"Results exported to:\n{filename}")
                
            except Exception as e:
                self.log(f"Export failed: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_text(self, text_widget):
        text = text_widget.get(1.0, tk.END)
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text)
                
                self.log(f"Text exported to: {filename}")
                
            except Exception as e:
                self.log(f"Export failed: {str(e)}")
    
    def stop_fuzzing(self):
        if hasattr(self, 'fuzzer') and self.fuzzer:
            self.fuzzer.stop()
        if hasattr(self, 'intelligent_fuzzer') and self.intelligent_fuzzer:
            self.intelligent_fuzzer.stop()
        
        self.log("Fuzzing stopped")
        self.update_status("Fuzzing stopped", False)

def main():
    root = tk.Tk()
    root.title("CTF PWN Tool - Advanced Version")
    
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
    except:
        pass
    
    app = CTFPwnToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()

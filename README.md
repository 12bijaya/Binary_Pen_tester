# Binary Vulnerability Scanner and Fuzzer

A comprehensive, professional-grade binary analysis, vulnerability scanning, and exploitation toolkit with advanced fuzzing capabilities, remote exploitation support, and real-time exploit execution. Designed for security researchers, penetration testers, CTF players, and binary exploitation enthusiasts.

---

## 📑 Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Installation](#installation)
4. [Getting Started](#getting-started)
5. [Detailed Feature Guide](#detailed-feature-guide)
6. [Usage Examples & Tutorials](#usage-examples--tutorials)
7. [Advanced Techniques](#advanced-techniques)
8. [Architecture & Design](#architecture--design)
9. [Troubleshooting](#troubleshooting)
10. [Security & Best Practices](#security--best-practices)
11. [FAQ](#faq)
12. [Version History](#version-history)

---

## Overview

The **Binary Vulnerability Scanner and Fuzzer** is an all-in-one exploitation toolkit that combines static analysis, dynamic fuzzing, interactive debugging, exploit generation, and real-time exploit execution into a single, unified GUI application. 

### What Makes This Tool Unique?

- **Completely Automated Fuzzing**: Detects format string vulnerabilities, buffer overflows, and automatically classifies memory leaks (Stack, Libc, PIE, Heap)
- **Remote Exploitation Support**: Seamlessly switch between local binaries and remote servers for both fuzzing and exploitation
- **Real-Time Exploit Runner**: Execute exploits directly from the GUI with live output, post-exploit command execution, and process control
- **Auto-Generated Exploits**: Automatically uses the loaded binary path in generated exploits - no manual editing required
- **User Input Detection**: Identifies exactly where your input appears on the stack during format string attacks
- **Professional-Grade Tools**: Integrated with industry-standard tools like `pwntools`, `ropper`, and `gdb`

### Who Is This For?

- **CTF Players**: Rapid binary exploitation during competitions
- **Security Researchers**: Comprehensive vulnerability discovery and analysis
- **Penetration Testers**: Authorized binary testing and exploit development
- **Students**: Learning binary exploitation, reverse engineering, and vulnerability research
- **Bug Bounty Hunters**: Finding vulnerabilities in authorized targets

---

## Key Features

### 📊 Binary Analysis Engine

The binary analysis engine provides comprehensive static analysis of executable files:

**Architecture Detection**:
- Automatically identifies x64, x86, ARM, and other architectures
- Adjusts exploit payloads and analysis techniques based on architecture
- Displays bit width (32-bit or 64-bit) for proper gadget selection

**Symbol Extraction**:
- Extracts function names and their memory addresses
- Identifies interesting functions (system, exec, printf, gets, strcpy, etc.)
- Useful for ret2win, ret2libc, and ROP chain construction

**Security Feature Detection**:
- **NX (No-Execute)**: Detects if stack is executable (shellcode viability)
- **PIE (Position Independent Executable)**: Identifies address randomization
- **Stack Canary**: Detects stack protection mechanisms
- **RELRO**: Identifies GOT protection levels (Full RELRO, Partial RELRO, No RELRO)
- **FORTIFY**: Detects fortified function implementations

**File Information**:
- Binary type (ELF, PE, etc.)
- Entry point address
- File size and sections
- Import/Export tables

### 🛡️ Vulnerability Scanner

Advanced static vulnerability detection with severity classification:

**Detection Categories**:
- **HIGH Severity**:
  - Lack of stack canaries (buffer overflow risk)
  - Executable stack (shellcode injection possible)
  - No ASLR/PIE (predictable addresses)
  - Dangerous function usage (gets, strcpy, sprintf)
  
- **MEDIUM Severity**:
  - Partial RELRO (GOT overwrite possible)
  - Format string functions without validation
  - Uninitialized memory usage
  
- **LOW Severity**:
  - Information disclosure potential
  - Deprecated function usage

**Interactive Details**:
- Click any vulnerability to see detailed explanation
- Recommended mitigations and exploitation techniques
- Related CVEs and references where applicable

### 🎯 Advanced Fuzzing System

#### Format String Fuzzing

The most powerful feature - automatically discovers format string vulnerabilities and extracts critical information:

**How It Works**:
1. **Input Marker Injection**: Sends `AAAAAAAA.%i$p` payloads to detect user input location
2. **Offset Iteration**: Tests offsets 1 through Max Offset (configurable, default 60)
3. **Output Capture**: Reads program output and parses hex addresses
4. **Leak Classification**: Analyzes each leaked address and classifies it:
   - **Stack Leak**: Addresses in typical stack range (0x7fff...)
   - **Libc Leak**: Addresses in libc range (identifiable by high-order bytes)
   - **PIE Leak**: Addresses in PIE executable range
   - **Heap Leak**: Addresses in heap range
   - **Small Integer**: Non-address values (e.g., counters, flags)
   - **NULL**: Empty/null values
5. **User Input Detection**: Identifies offsets where the marker (0x4141414141414141) appears - marking exact stack position
6. **Table Output**: Displays results in clean, readable format

**Usage**:
```
Interactive Tab → Send input → Click "Fuzz This Input" → Select "Format String"
→ Set Max Offset (60 recommended) → View results table

Example Output:
[*] FORMAT STRING FUZZING RESULTS (1-60)
=========================================
Offset 1  → Stack/Libc leak    → 0x7f80f7c08963
Offset 2  → Stack/Libc leak    → 0x7ffec3679f30
Offset 3  → Stack/Libc leak    → 0x7f5f22e0a7a0
Offset 4  → NULL               → (nil)
Offset 5  → NULL               → (nil)
Offset 6  → ** USER INPUT DETECTED ** → 0x4141414141414141
Offset 7  → Unknown            → 0x702437
Offset 8  → Stack/Libc leak    → 0x7ffd34ab0e80
```

**Why This Matters**:
- Offset 6 tells you where to place your payload
- Stack/Libc leaks help defeat ASLR
- Knowing leak types guides exploit strategy

#### Buffer Overflow Fuzzing

Automatically discovers buffer overflow vulnerabilities and calculates exact offsets:

**How It Works**:
1. **Incremental Testing**: Starts with small payloads, gradually increases
2. **Pattern Generation**: Uses cyclic patterns for offset identification
3. **Crash Detection**: Monitors for segmentation faults
4. **Offset Calculation**: Determines exact bytes needed to overwrite return address
5. **Results Display**: Shows crash information and calculated offset

**Usage**:
```
Interactive Tab → Send inputs normally → Click "Fuzz This Input" → Select "Buffer Overflow"
→ Wait for crash detection → Review offset

Example Output:
[*] CRASH DETECTED at payload size 120
[*] Calculated offset: 112 bytes
[*] Use this offset in your exploit to overwrite return address
```

**Why This Matters**:
- Immediate offset calculation for exploit development
- No manual debugging required
- Accurate results for exploit generation

### ⚡ Interactive Mode (Local & Remote)

The interactive mode is the heart of dynamic binary analysis and fuzzing:

#### Local Binary Mode

**What It Does**:
- Spawns the binary as a subprocess on your local machine
- Captures stdout and stderr in real-time
- Allows sending custom input interactively
- Maintains interaction history for fuzzing

**When to Use**:
- Testing local binaries during development
- CTF challenges you've downloaded
- Analyzing binaries before remote exploitation
- Debugging exploit payloads

**Technical Details**:
- Uses `subprocess.Popen()` with `PIPE` for I/O
- Multi-threaded output capture (non-blocking GUI)
- Proper process termination handling
- Stdin/stdout/stderr separation

#### Remote Server Mode

**What It Does**:
- Connects to remote TCP servers using `pwntools.remote()`
- Sends and receives data over network connection
- Works exactly like local mode from user perspective
- Enables remote fuzzing and exploitation

**When to Use**:
- CTF challenges running on remote servers
- Penetration testing (with authorization)
- Real-world exploitation scenarios
- Testing production services (authorized only)

**Technical Details**:
- Uses `pwntools` for robust connection handling
- Automatic reconnection on errors
- Timeout management
- Network I/O buffering

**Setup**:
```
1. Select "Remote Server" radio button
2. Enter IP address (e.g., 192.168.1.100, ctf.example.com)
3. Enter Port (e.g., 1337, 31337, 9001)
4. Click "Start/Reset Session"
5. Watch for connection confirmation
6. Interact normally - send inputs, fuzz, analyze
```

### 💣 Exploit Generator & Exploit Runner

#### Exploit Generator

Automatically generates Python exploit scripts using pwntools:

**Supported Exploit Types**:

1. **Buffer Overflow**:
   - Template includes offset calculation
   - Payload construction with p64/p32
   - Return address overwrite
   - Auto-detects architecture for pack format

2. **Format String**:
   - Automated FmtStr attack using pwntools
   - GOT overwrite template
   - Offset configuration
   - Write-what-where primitive

3. **ROP Chain**:
   - Gadget finding with ROPgadget
   - Chain construction template
   - Register control examples
   - Function call sequences

4. **Ret2Win**:
   - Simple return address overwrite to target function
   - Symbol address lookup
   - Stack alignment examples

5. **Ret2Libc**:
   - Two-stage exploitation template
   - Libc leak stage
   - system() call with /bin/sh
   - ASLR bypass technique

6. **Ret2PLT**:
   - PLT/GOT leak template
   - Address disclosure
   - Return to main for second payload

7. **SROP (Sigreturn-Oriented Programming)**:
   - Signal frame forgery
   - Register control via sigreturn
   - Syscall invocation

8. **Shellcode Injection**:
   - NX bypass techniques
   - Architecture-specific shellcode
   - ROP-to-shellcode transitions

9. **Ret2CSU**:
   - __libc_csu_init exploitation
   - Register loading gadgets
   - Function pointer control

**Auto-Loaded Binary Paths**:
Every generated exploit automatically includes the path to your loaded binary:
```python
# Generated exploit automatically uses loaded binary
binary_path = '/home/user/challenges/vuln_binary'  # Auto-filled!
context.binary = binary = ELF(binary_path, checksec=False)
```

No more manual find-and-replace! Just load your binary, generate exploit, and run.

#### Exploit Runner - The Game Changer

Execute exploits directly from the GUI with full control:

**Configuration Options**:

1. **Target Type**:
   - **Local Binary**: Execute exploit against local binary file
   - **Remote Server**: Connect exploit to remote IP:Port

2. **Network Settings** (Remote mode):
   - **IP Address**: Target server IP or hostname
   - **Port**: Target service port
   - Examples: `127.0.0.1:1337`, `ctf.server.com:31337`

3. **Runtime Arguments**:
   - **Args**: Command-line arguments to pass to the exploit
   - Example: `--flag admin --debug`

4. **Post-Exploit Commands** ⭐:
   - Commands to execute after successful exploitation
   - Separated by semicolons
   - Example: `id; whoami; cat flag.txt`
   - Example: `ls -la; cat /etc/passwd; uname -a`
   
   **How It Works**:
   - After exploit gains code execution
   - Commands are sent to the spawned shell
   - Output is captured and displayed
   - Perfect for automated flag capture

5. **Debug Mode**:
   - **Debug (GDB)**: Launch exploit under GDB for debugging
   - Useful for troubleshooting failed exploits

**Control Buttons**:

- **▶ Run Exploit** (Green):
  - Executes the exploit script
  - Shows real-time output
  - Runs post-exploit commands on success
  
- **⏹ Stop** (Red):
  - Terminates running exploit
  - Kills the process immediately
  - Useful if exploit hangs
  
- **🗑️ Clear Output** (Gray):
  - Clears the output console
  - Prepares for next run

**Output Console**:
- Real-time stdout/stderr capture
- Color-coded status messages:
  - `[*]` Info messages (blue)
  - `[+]` Success messages (green)
  - `[-]` Failure messages (red)
  - `[!]` Warning messages (orange)
- Scrollable history
- Copy-paste support

**Real-World Example**:
```
Scenario: CTF challenge with remote flag checker

1. Load local copy of binary for analysis
2. Fuzz to find vulnerability (format string at offset 6)
3. Generate Format String exploit
4. Exploit Runner Configuration:
   - Target: Remote Server
   - IP: ctf.challenge.com
   - Port: 31337
   - Post-Exploit Cmds: cat /home/ctf/flag.txt
5. Click "Run Exploit"
6. Watch output console:
   [*] Connecting to ctf.challenge.com:31337
   [*] Sending format string payload
   [+] Got shell!
   [*] Executing: cat /home/ctf/flag.txt
   [+] flag{your_flag_here}
7. Copy flag, submit, profit! 🚩
```

### 🔧 ROP Gadget Finder

Discover ROP gadgets for exploit development:

**Features**:
- **Ropper Integration**: Uses ropper (if installed) for advanced gadget finding
- **Automatic Fallback**: Falls back to objdump if ropper unavailable
- **Configurable Results**: Set max gadgets (up to 500)
- **Address Display**: Shows exact memory addresses
- **Gadget Details**: Click gadgets to see full instruction sequences

**Common Gadget Types**:
- `pop rdi; ret` - Set RDI register (first argument x64)
- `pop rsi; pop r15; ret` - Set RSI register (second argument)
- `pop rdx; ret` - Set RDX register (third argument)
- `ret` - Simple return (stack alignment)
- `syscall; ret` - System call invocation
- `call [register]` - Function pointer calls

**Usage in Exploits**:
```python
# Find gadgets
pop_rdi = 0x401234  # From gadget finder
ret = 0x401000

# Build ROP chain
payload = b"A" * offset
payload += p64(pop_rdi)
payload += p64(bin_sh_address)
payload += p64(system_address)
```

---

## Installation

You have **two options** to use this tool:
1. **Using the Pre-built Binary** (Recommended for quick start - no Python required)
2. **Running from Source** (For development and customization)

---

### Option 1: Using the Pre-built Binary Executable

The easiest way to use this tool on Linux is with the pre-built binary. No Python installation or dependencies required!

#### Quick Start (Binary):

```bash
# Download or obtain the binary-scanner executable
# Make it executable
chmod +x binary-scanner

# Run the tool
./binary-scanner
```

**System Requirements for Binary**:
- Linux (x64) - Ubuntu, Debian, Arch, Fedora, Kali, or similar
- External tools: `binutils`, `file`, `gdb` (optional), `checksec` (optional)

**Install Required System Tools**:

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y binutils file gdb checksec
```

On Arch Linux:
```bash
sudo pacman -S binutils file gdb checksec
```

On Fedora/RHEL:
```bash
sudo dnf install binutils file gdb
# checksec may need to be installed separately
```

That's it! The binary includes all Python dependencies bundled inside.

---

### Option 2: Running from Source

If you want to modify the code or contribute to development, follow these steps:

#### Step 1: System Requirements

**Operating Systems**:
- Linux (Ubuntu, Debian, Arch, Fedora, Kali)
- macOS (10.14+)
- Windows (via WSL2)

**Python Version**:
- Python 3.7 or higher (3.9+ recommended)

#### Step 2: Install System Dependencies on Linux

The tool requires several system utilities for binary analysis. Install them based on your Linux distribution:

**On Ubuntu/Debian**:
```bash
# Update package list
sudo apt-get update

# Install binary analysis tools
sudo apt-get install -y binutils file gdb checksec

# Install Python 3 and pip
sudo apt-get install -y python3 python3-pip python3-dev

# Install build tools (required for pwntools compilation)
sudo apt-get install -y build-essential libssl-dev libffi-dev

# Install tkinter for GUI support
sudo apt-get install -y python3-tk
```

**On Arch Linux**:
```bash
# Install binary analysis tools
sudo pacman -S binutils file gdb checksec

# Install Python and development tools
sudo pacman -S python python-pip base-devel tk

# Install pwntools dependencies
sudo pacman -S openssl libffi
```

**On Fedora/RHEL/CentOS**:
```bash
# Install binary analysis tools
sudo dnf install binutils file gdb

# Install Python and development tools
sudo dnf install python3 python3-pip python3-devel gcc

# Install tkinter
sudo dnf install python3-tkinter

# Install build dependencies
sudo dnf install openssl-devel libffi-devel
```

**On Kali Linux**:
```bash
# Kali usually has most tools pre-installed, but verify:
sudo apt-get update
sudo apt-get install -y binutils file gdb checksec python3-pip python3-dev python3-tk
```

#### Step 3: Install Python Dependencies

```bash
# Navigate to project directory
cd /path/to/cw1

# Option A: Install directly (quick)
pip3 install -r requirements.txt

# Option B: Use virtual environment (recommended for isolation)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

**What gets installed**:
- `pwntools` - Core exploitation framework (binary analysis, process control, networking)
- `ropper` (optional) - Advanced ROP gadget finding

**Manual installation** (if requirements.txt is unavailable):
```bash
pip3 install pwntools ropper
```

#### Step 4: Verify Installation

```bash
# Test the GUI tool
python3 scanner.py

# Test the CLI tool
python3 cli_scanner.py vulnbank.elf

# You should see the GUI window open or CLI menu
# If you see errors, check the troubleshooting section below
```

---

### Troubleshooting Installation Issues

**Issue: `ModuleNotFoundError: No module named 'tkinter'`**
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Arch
sudo pacman -S tk

# Fedora
sudo dnf install python3-tkinter
```

**Issue: `pwntools` installation fails**
```bash
# Install build dependencies first
sudo apt-get install build-essential python3-dev libssl-dev libffi-dev
pip3 install --upgrade pip
pip3 install pwntools
```

**Issue: Binary executable won't run**
```bash
# Make sure it's executable
chmod +x binary-scanner

# Check if required system tools are installed
which readelf objdump nm strings  # Should show paths
```

**Issue: Permission denied when running tools**
```bash
# Run with sudo if analyzing system binaries
sudo ./binary-scanner

# Or change binary permissions
chmod +x /path/to/target/binary
```


---

## Getting Started

### Launching the Tool

**If using the binary executable**:
```bash
./binary-scanner
```

**If running from source**:
```bash
python3 scanner.py
```

### First Steps

1. **Load a binary**:
   - Click "📁 Load Binary File" in the left sidebar
   - Navigate to your test binary
   - Click "Open"

2. **Analyze the binary**:
   - Click "🔍 Analyze Binary" in the left sidebar
   - Review the Analysis tab for security features
   - Note any interesting functions or missing protections

3. **Find vulnerabilities**:
   - Click "🛡️ Vulnerability Scan"
   - Review the Vulnerabilities tab
   - Click individual vulnerabilities for details

4. **Interactive testing**:
   - Go to Interactive tab
   - Click "Start/Reset Session" (Local Binary mode)
   - Send test inputs and observe output

5. **Fuzz for bugs**:
   - After sending inputs, click "Fuzz This Input"
   - Select fuzzing type (Format String or Buffer Overflow)
   - Review results

### Quick Test Example

Let's test with a simple vulnerable program:

```c
// vulnerable.c
#include <stdio.h>
int main() {
    char buffer[64];
    printf("Enter name: ");
    gets(buffer);  // Vulnerable!
    printf("Hello, %s!\n", buffer);
    return 0;
}
```

Compile without protections:
```bash
gcc vulnerable.c -o vulnerable -fno-stack-protector -z execstack -no-pie
```

Test with the tool:
1. Load `vulnerable` binary
2. Analyze → note "No stack canary" and "Executable stack"
3. Interactive → Start Session
4. Send normal input: `test`
5. Click "Fuzz This Input" → Buffer Overflow
6. Watch it detect crash and calculate offset
7. Generate exploit → Buffer Overflow
8. Run exploit!

---

## Detailed Feature Guide

### Binary Analysis Tab

**Purpose**: Static analysis of binary file properties

**Information Displayed**:
- **File Path**: Full path to loaded binary
- **Architecture**: CPU architecture (x64, x86, ARM)
- **Bit Width**: 32-bit or 64-bit
- **File Type**: ELF, PE, etc.
- **Entry Point**: First instruction address
- **Security Features**:
  - NX (DEP): Stack executable or not
  - PIE: Position independent
  - Canary: Stack protection
  - RELRO: GOT protection level
- **Functions**: Symbol table with addresses
- **Sections**: Binary sections (.text, .data, .bss, etc.)

**Actions**:
- **Re-analyze**: Refresh analysis (useful if binary changes)
- **Export**: Save analysis to JSON or TXT file

### Vulnerabilities Tab

**Purpose**: Identify potential security vulnerabilities

**Vulnerability Types Detected**:

1. **Buffer Overflow Risks**:
   - Dangerous functions: gets(), strcpy(), sprintf()
   - Missing stack canary
   - Recommendation: Use bounds-checked alternatives

2. **Format String Vulnerabilities**:
   - printf/scanf family used incorrectly
   - No format string validation
   - Recommendation: Use static format strings

3. **Memory Protection Issues**:
   - Executable stack (NX disabled)
   - No ASLR/PIE
   - Recommendation: Enable modern protections

4. **GOT Overwrite Possibilities**:
   - Partial or No RELRO
   - GOT/PLT can be modified
   - Recommendation: Full RELRO

**User Interface**:
- **List View**: Shows all vulnerabilities with severity
- **Detail Pane**: Click vulnerability for full description
- **Color Coding**:
  - Red: HIGH severity
  - Orange: MEDIUM severity
  - Yellow: LOW severity

### Interactive Tab - Deep Dive

**Purpose**: Dynamically interact with binaries (local or remote)

**Connection Setup**:

**Local Binary Mode**:
1. Ensure binary is loaded (📁 Load Binary File)
2. Select "Local Binary" radio button (default)
3. Click "Start/Reset Session"
4. Binary spawns in background
5. Initial output appears (banner, prompts, etc.)

**Remote Server Mode**:
1. Select "Remote Server" radio button
2. Enter IP address:
   - IPv4: `192.168.1.100`
   - Domain: `ctf.example.com`
   - Localhost: `127.0.0.1`
3. Enter Port: `1337`, `31337`, `9001`, etc.
4. Click "Start/Reset Session"
5. Connection established
6. Server banner appears

**Sending Input**:
1. Type in "Input:" field
2. Press Enter or click "Send"
3. Input sent automatically with newline
4. Output appears in console below

**Fuzz This Input - Detailed Workflow**:

**When to Use**:
- After establishing normal interaction
- You've sent some inputs and got responses
- Ready to test for vulnerabilities

**Format String Option**:
1. Click "Fuzz This Input"
2. Select "Format String"
3. Dialog appears with Max Offset option
4. Default: 60 (good for most cases)
5. Set higher (100+) if you want deeper stack inspection
6. Click "Start Format String Fuzzing"
7. Watch results populate in real-time
8. Review:
   - Leak locations and types
   - User input offset (marked with **)
   - Addresses for defeating ASLR

**Buffer Overflow Option**:
1. Click "Fuzz This Input"
2. Select "Buffer Overflow"
3. Fuzzing starts automatically
4. Incremental payload sizes sent
5. Monitors for crashes (segfault)
6. When crash detected:
   - Shows crash payload size
   - Calculates exact offset
   - Displays in results
7. Use offset in exploit generation

**Interaction History**:
- All sent inputs are recorded
- Used for replay during fuzzing
- Ensures fuzzer reaches vulnerable code path
- Example: If program asks for PIN, then name, fuzzer replays PIN interaction before fuzzing name input

### Exploit Tab - Complete Guide

**Layout**:
- **Top Section**: Exploit editor (write/edit exploit code)
- **Bottom Section**: Exploit runner (configuration and execution)

**Exploit Editor**:
- **Generate Templates**: Dropdown + Generate button
- **Syntax Highlighting**: Python code highlighting
- **Edit Freely**: Modify generated exploits as needed
- **Save/Load**: Export/import exploit scripts

**Exploit Runner Configuration**:

**Target Selection**:
- **Local Binary**: 
  - Uses loaded binary path automatically
  - Runs exploit as subprocess
  - Fast iteration, local debugging
  
- **Remote Server**:
  - Enter IP and Port
  - Connects over TCP
  - For CTF/real targets

**Arguments Field**:
- Extra args passed to exploit script
- Example uses:
  - `--timeout 5` - Custom timeout
  - `--debug` - Enable debug output
  - `--offset 120` - Override offset

**Post-Exploit Commands - Power Feature**:

**What It Does**:
After successful exploitation (shell spawned), automatically executes commands

**Common Use Cases**:

1. **Flag Capture (CTF)**:
   ```
   cat flag.txt
   ```

2. **Multi-Step Retrieval**:
   ```
   cd /home/ctf; ls -la; cat flag.txt
   ```

3. **Information Gathering**:
   ```
   id; uname -a; cat /etc/passwd; ifconfig
   ```

4. **Privilege Escalation Enumeration**:
   ```
   find / -perm -4000 2>/dev/null; sudo -l; cat /etc/shadow
   ```

**How Commands Work**:
- Separated by semicolons (`;`)
- Executed sequentially after shell spawn
- Output captured and displayed
- If one fails, others still execute

**Debug Mode**:
- Checkbox: "Debug (GDB)"
- Launches exploit under GDB
- Useful for:
  - Debugging crashes
  - Inspecting memory
  - Single-stepping through exploit
  - Finding where exploit fails

**Execution**:
1. Write/generate exploit
2. Configure target (Local/Remote)
3. Set post-exploit commands
4. Click "▶ Run Exploit"
5. Watch output console for:
   - Connection status
   - Exploit progress
   - Shell interaction
   - Post-exploit command results
   - Success/failure indicators

**Output Console Interpretation**:
```
[*] Starting exploit...        # Info
[*] Exploit saved to /tmp/...  # Info
[*] Running: python3 /tmp/...  # Command being run
[*] Connected to target        # Success
[+] Got shell!                 # Success
[*] Executing: cat flag.txt    # Post-exploit command
flag{example_flag_here}        # Command output
[+] Exploit completed!         # Final success
```

### ROP Gadgets Tab

**Purpose**: Find useful gadgets for ROP chain construction

**Configuration**:
- **Max Results**: Spinner to set gadget limit (default 100, max 500)
- Higher numbers = more gadgets but slower search

**Search Process**:
1. Click "Find ROP Gadgets"
2. Tool tries ropper first (if installed)
3. Falls back to objdump if ropper unavailable
4. Parses gadget output
5. Displays in list with addresses

**Gadget Display**:
- Format: `0x401234: pop rdi; ret`
- Click gadget for full details
- Export functionality for saving

**Using Gadgets in Exploits**:
```python
# Copy addresses from gadget finder
pop_rdi = 0x401234
pop_rsi_r15 = 0x401232
ret = 0x401011

# Build chain
rop_chain = p64(pop_rdi)
rop_chain += p64(arg1)
rop_chain += p64(pop_rsi_r15)
rop_chain += p64(arg2)
rop_chain += p64(0)  # r15 junk
rop_chain += p64(target_function)
```

### Code Editor Tab

**Purpose**: Write custom exploit scripts from scratch

**Features**:
- Syntax highlighting for Python
- Visible cursor (white on dark background)
- Load existing scripts
- Save scripts to disk
- Full editing capabilities

**Use Cases**:
- Modify generated exploits extensively
- Write completely custom exploits
- Import exploits from other sources
- Collaborative exploit development

### Log Tab

**Purpose**: Track all tool activity and output

**Information Logged**:
- Binary load events
- Analysis start/complete
- Vulnerability scan results
- Fuzzing progress
- Exploit generation
- Errors and warnings

**Actions**:
- **Clear Log**: Remove all history
- **Export Log**: Save log to file for reporting

---

## Usage Examples & Tutorials

### Tutorial 1: Complete CTF Challenge - Local Buffer Overflow

**Scenario**: You have a local binary with a buffer overflow. Find the vulnerability, calculate offset, generate exploit, run it.

**Step-by-Step**:

1. **Load the binary**:
   ```
   📁 Load Binary File → Navigate to challenge.bin → Open
   ```

2. **Analyze security features**:
   ```
   Click "🔍 Analyze Binary"
   Review Analysis tab
   Note: No stack canary, No PIE (good for exploitation!)
   ```

3. **Scan for vulnerabilities**:
   ```
   Click "🛡️ Vulnerability Scan"
   Review Vulnerabilities tab
   See: "HIGH - Buffer Overflow Risk - gets() function used"
   ```

4. **Interactive testing**:
   ```
   Go to Interactive tab
   Ensure "Local Binary" selected
   Click "Start/Reset Session"
   
   Output shows:
   [*] Started session for challenge.bin
   Enter your name: 
   ```

5. **Send test input**:
   ```
   Type: test_user
   Press Enter
   
   Output:
   Hello, test_user!
   ```

6. **Fuzz for offset**:
   ```
   Click "Fuzz This Input"
   Select "Buffer Overflow"
   
   Watch output:
   [*] BUFFER OVERFLOW FUZZING
   Testing size 10... OK
   Testing size 20... OK
   Testing size 50... OK
   Testing size 100... OK
   Testing size 110... OK
   Testing size 115... OK
   Testing size 120... CRASH!
   [+] CRASH DETECTED at size 120
   [+] Calculated offset: 112 bytes
   ```

7. **Find a target**:
   ```
   Go to Analysis tab
   Look for interesting function (e.g., "win" at 0x401234)
   ```

8. **Generate exploit**:
   ```
   Go to Exploit tab
   Select "Ret2Win" from dropdown
   Click "Generate Exploit"
   
   Exploit appears in editor with correct binary path
   ```

9. **Edit exploit**:
   ```python
   # Generated exploit auto-filled:
   binary_path = '/home/user/ctf/challenge.bin'  # ✓ Correct
   offset = 112  # Change from default to calculated
   win_addr = 0x401234  # Found in analysis
   ```

10. **Run exploit**:
    ```
    Exploit Runner section:
    - Target: Local Binary (already set)
    - Post-Exploit Cmds: cat flag.txt
    - Click "▶ Run Exploit"
    
    Output console:
    [*] Starting exploit...
    [+] Got shell!
    [*] Executing: cat flag.txt
    flag{buffer_0verfl0w_pwn3d}
    [+] Exploit completed successfully!
    ```

**Success!** 🎉 You captured the flag in under 5 minutes.

---

### Tutorial 2: Remote Format String Attack

**Scenario**: CTF challenge running on remote server. Format string vulnerability. Need to leak addresses and get flag.

**Step-by-Step**:

1. **Get challenge info**:
   ```
   Server: ctf.example.com
   Port: 31337
   ```

2. **Connect remotely**:
   ```
   Go to Interactive tab
   Select "Remote Server"
   IP: ctf.example.com
   Port: 31337
   Click "Start/Reset Session"
   
   Output:
   [*] Connected to ctf.example.com:31337
   ===== Format String Challenge =====
   Enter message:
   ```

3. **Test for format string**:
   ```
   Send: %p
   
   Response:
   You said: 0x7ffd1234
   
   Confirmed format string vulnerability!
   ```

4. **Fuzz to find details**:
   ```
   Click "Fuzz This Input"
   Select "Format String"
   Max Offset: 60
   Click "Start"
   
   Results:
   Offset 1  → Stack/Libc leak → 0x7f8f9c0a7963
   Offset 2  → Stack/Libc leak → 0x7ffd2341f930
   Offset 6  → ** USER INPUT DETECTED ** → 0x4141414141414141
   Offset 8  → Stack/Libc leak → 0x7f8f9c0a7a00
   Offset 12 → Stack/Libc leak → 0x7f8f9c0a7100  (likely libc)
   ```

5. **Strategy**:
   ```
   - User input at offset 6 (perfect for write-what-where)
   - Libc leak at offset 12 (for ASLR defeat)
   - Will use format string to:
     a) Leak libc
     b) Calculate system() address
     c) Overwrite GOT entry to system()
     d) Call with "/bin/sh"
   ```

6. **Generate exploit**:
   ```
   Go to Exploit tab
   Select "Format String"
   Click "Generate Exploit"
   ```

7. **Customize exploit**:
   ```python
   # Edit the generated template
   offset = 6  # From fuzzing
   
   # First, leak libc
   payload1 = f"%{12}$p"
   
   # Then, use calculated addresses for GOT overwrite
   # (detailed format string exploitation)
   ```

8. **Configure runner**:
   ```
   Target: Remote Server
   IP: ctf.example.com
   Port: 31337
   Post-Exploit Cmds: cat /home/ctf/flag.txt
   ```

9. **Run exploit**:
   ```
   Click "▶ Run Exploit"
   
   Output:
   [*] Connecting to ctf.example.com:31337
   [*] Leaking libc address...
   [+] Libc base: 0x7f8f9c000000
   [*] Calculating system() address...
   [+] system(): 0x7f8f9c04fa00
   [*] Overwriting GOT entry...
   [+] GOT overwrite successful!
   [*] Triggering system("/bin/sh")...
   [+] Shell spawned!
   [*] Executing: cat /home/ctf/flag.txt
   flag{f0rm4t_str1ng_m4st3r}
   [+] Exploit completed!
   ```

**Success!** 🚩 Remote exploitation complete.

---

### Tutorial 3: Multi-Stage ROP Exploitation

**Scenario**: Binary with NX enabled. Need to build ROP chain to call system("/bin/sh").

**Step-by-Step**:

1. **Load and analyze**:
   ```
   Load binary
   Analysis tab shows:
   - NX: Enabled (can't execute shellcode)
   - PIE: Disabled (good for ROP)
   - Partial RELRO (GOT overwrite possible)
   ```

2. **Find buffer overflow**:
   ```
   Interactive tab → Test → Fuzz
   Offset found: 120 bytes
   ```

3. **Find ROP gadgets**:
   ```
   Go to ROP Gadgets tab
   Max Results: 100
   Click "Find ROP Gadgets"
   
   Found:
   0x401234: pop rdi; ret
   0x401236: pop rsi; pop r15; ret
   0x401011: ret
   ```

4. **Generate ROP exploit**:
   ```
   Exploit tab → Select "Ret2Libc"
   Generate → Auto-generates two-stage attack
   ```

5. **Customize with gadgets**:
   ```python
   pop_rdi = 0x401234  # From gadget finder
   ret = 0x401011
   
   # Stage 1: Leak libc
   payload1  = b"A" * 120
   payload1 += p64(pop_rdi)
   payload1 += p64(binary.got['puts'])
   payload1 += p64(binary.plt['puts'])
   payload1 += p64(binary.symbols['main'])
   
   # Stage 2: Call system("/bin/sh")
   # (after calculating libc base from leak)
   ```

6. **Execute**:
   ```
   Configure runner
   Set post-exploit: id; whoami; cat flag.txt
   Run exploit
   
   Output shows:
   - Libc leak successful
   - system() address calculated
   - ROP chain executed
   - Shell spawned
   - Flag captured
   ```

---

## Advanced Techniques

### Defeating ASLR with Information Leaks

**Problem**: Modern systems randomize addresses (ASLR/PIE)

**Solution**: Use format string or other leak to defeat randomization

**Technique**:
1. Use fuzzing to find leak offset
2. Classify leak type (Stack, Libc, PIE)
3. Calculate base address from leak
4. Compute target addresses using known offsets
5. Execute exploitation with calculated addresses

**Example**:
```python
# Leak from offset 12
leak = u64(p.recvline().strip().ljust(8, b'\x00'))

# Identify as libc leak (starts with 0x7f)
libc_base = leak - libc.symbols['puts']  # Known offset

# Calculate other addresses
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# Now use in exploit
```

### Chaining Exploits

**Combine multiple vulnerabilities for maximum impact**:

1. **Format String → Buffer Overflow**:
   - Use format string to leak addresses
   - Use buffer overflow with leaked addresses for ROP

2. **Information Disclosure → Code Execution**:
   - Leak canary, PIE base, libc
   - Craft perfect buffer overflow to bypass all protections

3. **Partial Overwrite Techniques**:
   - Overwrite only lower bytes (bypass ASLR partially)
   - Useful when full address unknown

### Automating Flag Capture

**Use post-exploit commands strategically**:

```bash
# Search entire filesystem for flag
find / -name "*flag*" 2>/dev/null; cat $(find / -name "*flag*" 2>/dev/null)

# Common CTF locations
cat /home/ctf/flag.txt; cat /root/flag.txt; cat /flag.txt; cat flag.txt

# Enumerate and exfiltrate
ls -la; cat flag*; cat *flag*; env | grep FLAG
```

### Remote Fuzzing at Scale

**Fuzz multiple inputs on remote server**:

1. Connect to remote server
2. Navigate through menu/prompts
3. Fuzz each input systematically
4. Document findings
5. Build comprehensive exploit

---

## Architecture & Design

### System Architecture

```
┌─────────────────────────────────────────┐
│         Tkinter GUI (Main Loop)         │
│  ┌────────────┐  ┌──────────────────┐   │
│  │   Tabs     │  │  Control Buttons │   │
│  └────────────┘  └──────────────────┘   │
└───────┬─────────────────────┬───────────┘
        │                     │
        ▼                     ▼
┌────────────────┐    ┌──────────────────┐
│ Analysis Engine│    │  Fuzzing Engine  │
│  - Binary Scan │    │  - Format String │
│  - Vuln Detect │    │  - Buffer Ovrflw │
│  - ROP Gadgets │    │  - Remote Fuzz   │
└────────────────┘    └──────────────────┘
        │                     │
        ▼                     ▼
┌─────────────────────────────────────────┐
│         Process Management              │
│  - subprocess (local)                   │
│  - pwntools remote (network)            │
│  - threading (non-blocking I/O)         │
└─────────────────────────────────────────┘
```

### Class Structure

**BinaryAnalyzer**:
- Parses binary files
- Extracts symbols, sections
- Detects architecture and protections

**VulnerabilityScanner**:
- Static analysis for vulnerabilities
- Checks for dangerous functions
- Evaluates security features

**InteractiveSession**:
- Manages process I/O
- Supports local and remote connections
- Maintains interaction history

**ExploitGenerator**:
- Template-based exploit generation
- Auto-fills binary paths
- Architecture-aware payloads

### Threading Model

- **Main Thread**: GUI event loop (Tkinter)
- **I/O Threads**: Process output readers (non-blocking)
- **Fuzzing Threads**: Background fuzzing operations
- **Exploit Threads**: Background exploit execution

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Binary file not found"
**Cause**: Path incorrect or file doesn't exist  
**Solution**:
- Verify file exists: `ls -l /path/to/binary`
- Check permissions: `chmod +x /path/to/binary`
- Use absolute path

#### Issue: Remote connection fails
**Cause**: Server down, wrong IP/port, firewall  
**Solution**:
- Test connection: `nc -zv IP PORT`
- Verify IP and port are correct
- Check firewall: `sudo ufw status`
- Try telnet: `telnet IP PORT`

#### Issue: Fuzzing doesn't find crashes
**Cause**: Binary is actually secure, or insufficient testing  
**Solution**:
- Increase Max Offset for format string
- Try different input patterns
- Ensure you're fuzzing the right input
- Binary might actually be secure!

#### Issue: ROP gadgets not found
**Cause**: ropper not installed  
**Solution**:
```bash
pip install ropper
# Restart the tool
```

#### Issue: Exploit runner shows "Failed"
**Cause**: Various - bad exploit, connection issue, wrong target  
**Solution**:
- Check output console for specific error
- Verify target type (Local vs Remote)
- Test exploit manually: `python3 exploit.py`
- Enable Debug (GDB) mode

#### Issue: Post-exploit commands don't execute
**Cause**: Exploit didn't get shell, or shell exited  
**Solution**:
- Verify exploit actually succeeded
- Check if shell is interactive
- Try simpler command first: `id`
- Add delays: `sleep 1; cat flag.txt`

#### Issue: GUI freezes
**Cause**: Not actually frozen - long operation in progress  
**Solution**:
- Wait for operation to complete
- Check Log tab for progress
- Use Stop button if available

---

## Security & Best Practices

### Legal and Ethical Guidelines

⚠️ **CRITICAL**: Only use this tool on:
- Your own binaries
- CTF challenges you're authorized to participate in
- Systems you have explicit written permission to test
- Educational lab environments

**Never**:
- Test production systems without authorization
- Attack others' systems
- Use in malicious or illegal activities

### Safe Testing Practices

1. **Isolated Environment**:
   ```bash
   # Use VMs for untrusted binaries
   # Recommended: VirtualBox, VMware, Docker
   ```

2. **Network Isolation**:
   - Disable internet for suspicious binaries
   - Use host-only network for testing
   - Monitor network traffic

3. **Backup Important Data**:
   - Before testing, backup your work
   - Use snapshots if in VM

4. **Understand the Code**:
   - Review generated exploits before running
   - Understand what post-exploit commands do
   - Don't blindly run unknown exploits

### Responsible Disclosure

If you find a real vulnerability:
1. Document the vulnerability
2. Create a proof-of-concept
3. Contact the vendor/maintainer privately
4. Allow time for patch (typically 90 days)
5. Publish details only after fix is available

---

## FAQ

**Q: Can I use this for CTFs?**  
A: Yes! That's a primary use case. Perfect for rapid binary exploitation.

**Q: Does this work on Windows binaries?**  
A: Yes, but best results on Linux. For Windows PE files, use in WSL.

**Q: How accurate is the fuzzing?**  
A: Very accurate for format string and buffer overflow detection. May not catch all vulnerability types.

**Q: Can I export exploits?**  
A: Yes, generated exploits are standard Python scripts you can save and modify.

**Q: Is internet required?**  
A: Only for remote exploitation. Local binary analysis works offline.

**Q: Can I add custom exploit templates?**  
A: Currently no, but you can edit generated exploits in the Code Editor tab.

**Q: What about heap vulnerabilities?**  
A: Current focus is stack-based vulnerabilities. Heap exploitation coming in future versions.

**Q: Does it support multi-architecture?**  
A: Yes, auto-detects x64/x86. Limited support for ARM detection.

---

## Version History

### v4.0 (Current)
**Release Date**: February 2026

**Major Features**:
- ✨ Exploit Runner with real-time execution
- ✨ Post-Exploit command automation
- ✨ Remote Server support for fuzzing and exploitation
- ✨ Enhanced format string fuzzing with leak classification
- ✨ User input offset detection in format string attacks
- ✨ Configurable fuzzing ranges (Max Offset spinbox)
- ✨ Auto-loaded binary paths in generated exploits
- ✨ Improved Local/Remote mode clarity
- ✨ Code editor with visible cursor
- 🐛 Fixed interactive mode connection issues
- 🐛 Resolved process management memory leaks

### v3.0
**Release Date**: January 2026

**Features**:
- ROP gadget tab with ropper integration
- Intelligent fuzzing with offset calculation
- Multi-threaded processing for responsive GUI
- Comprehensive export functionality
- Vulnerability scanner improvements

### v2.0
**Release Date**: December 2025

**Features**:
- Basic fuzzing capabilities
- Exploit generation framework
- Interactive shell mode

### v1.0
**Release Date**: November 2025

**Features**:
- Initial binary analysis framework
- Basic vulnerability detection
- GUI implementation

---

## Contributing

Found a bug? Want a feature? Here's how to help:

1. **Bug Reports**:
   - Describe the issue clearly
   - Provide steps to reproduce
   - Include screenshots if relevant
   - Share sample binary if possible (safe ones only!)

2. **Feature Requests**:
   - Explain the use case
   - Suggest implementation approach
   - Consider security implications

3. **Code Contributions**:
   - Follow existing code style
   - Add comments for complex logic
   - Test thoroughly

---

## License

Educational and authorized security testing only.  
Not for malicious use. Use responsibly and ethically.

---

## Credits

**Tools Integrated**:
- pwntools - Exploit development framework
- ropper - ROP gadget finder
- binutils - Binary analysis utilities

**Developed For**:
- Security researchers
- CTF players
- Penetration testers
- Binary exploitation students

---

**Binary Vulnerability Scanner and Fuzzer v4.0** - Your complete binary exploitation toolkit.

🚀 Happy Hacking (Ethically)!
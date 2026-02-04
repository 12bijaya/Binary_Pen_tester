# Binary Vulnerability Scanner and Fuzzer

A comprehensive binary analysis, vulnerability scanning, and exploitation toolkit with GUI support for penetration testing and security research.

## Features

### 📊 Binary Analysis
- **Architecture Detection**: Identifies processor architecture (x64, x86, ARM)
- **Symbol Extraction**: Extracts and displays functions with memory offsets
- **Security Analysis**: Detects protections (NX, PIE, Canary, RELRO)
- **File Information**: Comprehensive binary metadata and section information
- **Multi-format Support**: ELF, EXE, BIN, OUT, O, SO, DLL files

### 🛡️ Vulnerability Scanning
- **Static Analysis**: Identifies potential vulnerabilities in binary code
- **Security Features Detection**: Checks for modern protections
- **Detailed Reports**: Severity-based classification and descriptions
- **Interactive Details**: Click vulnerabilities to see detailed information

### 🎯 Fuzzing
- **Basic Fuzzing**: Random input generation and testing
- **Intelligent Fuzzing**: Menu-aware fuzzing with pattern discovery
- **Crash Detection**: Automatic detection and logging of crashes
- **Memory Leak Detection**: Identifies potential memory leaks
- **Offset Calculation**: Automatic buffer overflow offset detection

### ⚡ Interactive Mode
- **Live Binary Interaction**: Send custom input to running binary
- **Input/Output Monitoring**: Real-time output capture and display
- **Multi-threaded**: Non-blocking GUI with background I/O
- **Graceful Termination**: Proper process management

### 🔧 ROP Gadget Finder
- **Ropper Integration**: Advanced ROP gadget discovery (100+ gadgets)
- **Fallback Support**: Automatic fallback to objdump if ropper unavailable
- **Address Display**: Shows exact addresses for gadget locations
- **Assembly Breakdown**: Detailed instruction sequence analysis
- **Comprehensive Output**: Supports up to 500 gadgets per scan

### 💣 Exploit Generator
- **Buffer Overflow**: x64 and x86 payload generation
- **Format String**: Format string attack patterns
- **ROP Chains**: Return-oriented programming payloads
- **Command Injection**: Command-level exploitation templates
- **Architecture-Aware**: Adapts payloads to target architecture

### 📋 Logging & Export
- **Real-time Logging**: Live status updates and progress tracking
- **Export Functionality**: Save analysis results in JSON/TXT formats
- **Detailed Reports**: Comprehensive vulnerability and fuzzing reports

## Installation

### Prerequisites
- Python 3.7 or higher
- Linux, macOS, or WSL (Windows Subsystem for Linux)

### System Dependencies

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y binutils file gdb checksec
# Optional but recommended:
pip install ropper
```

#### macOS
```bash
brew install binutils file gdb
# Optional but recommended:
pip install ropper
```

#### Windows (WSL)
Use the Linux instructions above in your WSL terminal.

### Python Setup
```bash
# Clone or download the project
cd /path/to/Binary_Vulnerability_Scanner

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

### Running the Application
```bash
python3 scanner.py
```

### Workflow
1. **Load Binary**: Click "Open" to select a binary file to analyze
2. **Analyze**: Use the Analysis tab to examine binary properties
3. **Scan Vulnerabilities**: Run vulnerability scan to identify issues
4. **Fuzz**: Test the binary with fuzzing to find crashes
5. **Find ROP Gadgets**: Search for ROP gadgets for exploit development
6. **Generate Exploits**: Create payload code based on findings
7. **Interactive Mode**: Manually interact with the binary if needed

## Tab Guide

### 🔍 Analysis Tab
- Re-analyze loaded binary
- View architecture, security features, functions
- Export analysis results

### 🛡️ Vulnerabilities Tab
- Scan for vulnerabilities
- View severity levels (HIGH, MEDIUM, LOW)
- Get detailed descriptions and recommendations

### 🎯 Fuzzing Tab
**Basic Fuzzing:**
- Generate random inputs
- Configurable test case count
- Crash detection and logging

**Intelligent Fuzzing:**
- Menu-aware fuzzing
- Automatic option discovery
- Offset calculation

### ⚡ Interactive Tab
- Start interactive session
- Send custom input to binary
- View real-time output
- Monitor process state

### 💣 Exploit Tab
- Choose exploit type:
  - Buffer Overflow
  - Format String
  - ROP Chain
  - Command Injection
- Generate exploit code
- Copy and modify for your target

### 🔧 ROP Gadgets Tab
- Find ROP gadgets (up to 500)
- Filter by max results
- View gadget details
- Export gadget list
- Source information (ropper or objdump)

### 📋 Log Tab
- Real-time activity log
- Clear log history
- Export log messages

## Advanced Usage

### Finding Specific Vulnerabilities
1. Load binary in Analysis tab
2. Note functions and addresses
3. Use Fuzzing tab with menu options targeting vulnerable functions
4. Check detailed crash information for offset data

### Exploit Development
1. Run vulnerability scan
2. Use ROP Gadgets tab to find useful gadgets
3. Generate exploit code using Exploit tab
4. Modify with specific addresses and offsets
5. Test in Interactive tab

### Fuzzing for Crashes
1. Start with Basic Fuzzing (default 1000 test cases)
2. If crashes found, review details for patterns
3. Use Intelligent Fuzzing for more targeted testing
4. Note offsets from crash analysis

## Supported Binary Formats

| Format | Extension | Support |
|--------|-----------|---------|
| ELF | .elf, .out, .o | Full |
| Windows PE | .exe | Full |
| Raw Binary | .bin | Full |
| Shared Library | .so, .dll | Full |

## Architecture Support

- **x64** (AMD64): Full support
- **x86** (i386): Full support
- **ARM**: Detection and basic analysis
- **Other**: Detection only

## Dependencies & Tools

### Built-in (tkinter)
- GUI framework included with Python

### External (Linux/macOS)
- `file`: Binary type identification
- `readelf`: ELF section analysis
- `objdump`: Disassembly and gadget finding
- `nm`: Symbol extraction
- `strings`: String search

### Optional
- `ropper`: Enhanced ROP gadget finding
- `checksec`: Security feature detection
- `gdb`: Debugging support

## Troubleshooting

### "Binary file not found"
- Ensure the binary exists and path is correct
- Check file permissions (executable bit may be needed)

### "No vulnerabilities found"
- Binary may have all protections enabled
- Try Fuzzing tab for runtime vulnerabilities
- Some vulnerabilities require specific input

### ROP gadgets showing only few results
- Ensure ropper is installed: `pip install ropper`
- Increase max results spinner in ROP Gadgets tab
- Binary may be stripped of symbols

### Fuzzing crashes the GUI
- This is normal during fuzzing (process is running in background)
- Click "Stop Fuzzing" to halt operation
- Increase timeout values if binary is slow

### ropper not found
- Install with: `pip install ropper`
- Tool will fallback to objdump automatically

## Performance Tips

- **Smaller binaries analyze faster**: Start with simple test binaries
- **ROP gadget finding**: May take time for large binaries, increase timeout
- **Fuzzing**: Adjust test count based on binary complexity
- **Interactive mode**: Some binaries read exact byte count then exit (expected)

## Security Considerations

- **For authorized testing only**: Only analyze binaries you own or have permission to test
- **Isolated environment**: Use in isolated VMs for untrusted binaries
- **Crash analysis**: Some binaries may have destructive payloads
- **Fuzzing**: Can trigger unintended behavior, use with caution

## Example Workflow

```
1. Start the tool:
   python3 scanner.py

2. Load a vulnerable binary:
   File → Open → select ./vulnerable_binary

3. Analyze the binary:
   Analysis tab → Re-analyze

4. Scan for vulnerabilities:
   Vulnerabilities tab → Scan

5. Find ROP gadgets:
   ROP Gadgets tab → Find ROP Gadgets (max 100)

6. Generate exploit:
   Exploit tab → Select "ROP Chain" → Generate Exploit

7. Test interactively:
   Interactive tab → Start Interactive Analysis → Send input

8. Export results:
   Any tab → Export button
```

## Architecture

### Class Structure
- **BinaryAnalyzer**: Static binary analysis
- **VulnerabilityScanner**: Security scanning
- **ROPGadgetFinder**: Ropper integration with objdump fallback
- **Fuzzer**: Basic fuzzing engine
- **IntelligentFuzzer**: Menu-aware fuzzing
- **ExploitGenerator**: Multi-type exploit code generation
- **InteractiveShell**: Process management and I/O
- **CTFPwnToolGUI**: Main tkinter GUI

### Data Flow
1. User loads binary → BinaryAnalyzer parses it
2. Results displayed in Analysis tab
3. User runs scans → Specialized tools analyze
4. Results aggregated and displayed
5. Export saves to JSON or TXT

## Version

**v3.0** - Advanced binary analysis with ropper integration

## License

Educational and authorized security testing only.

## Contributing

For bug reports or feature requests, please provide:
1. Binary sample (if possible)
2. Expected behavior
3. Actual behavior
4. System information (OS, Python version)

## Support

### Common Issues

**Issue**: Interactive mode shows "Broken pipe"
**Solution**: Binary reads exact byte count then exits (normal behavior)

**Issue**: GUI freezes during fuzzing
**Solution**: GUI is responsive, fuzzing runs in background thread

**Issue**: Only 12 gadgets found instead of 100+
**Solution**: Install ropper: `pip install ropper`

## Research & Learning

This tool is designed for:
- Security research and education
- Penetration testing (with authorization)
- Binary analysis learning
- Exploit development practice
- CTF competition preparation

## Changelog

### v3.0
- Added ROP gadget tab with ropper integration
- Fixed interactive mode broken pipe errors
- Integrated full vulnerability scanning
- Added intelligent fuzzing with offset calculation
- Multi-threaded processing for responsive GUI
- Comprehensive export functionality

### v2.0
- Added basic fuzzing capabilities
- Implemented exploit generation
- Added interactive shell mode

### v1.0
- Initial binary analysis framework
- Basic vulnerability detection

---

**Binary Vulnerability Scanner and Fuzzer** - Professional-grade binary analysis toolkit for authorized security testing.

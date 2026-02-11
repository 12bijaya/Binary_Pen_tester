# Unit Testing Documentation

## Testing Strategy
The **Binary Vulnerability Scanner** follows a **Unit Testing** strategy to ensure individual components function correctly. Reliability is paramount for a security tool, as incorrect offset calculations or parsing errors could lead to failed exploits or false negatives.

## Testing Framework
- **Framework:** `unittest` (Standard Python library)
- **Directory:** `/tests`
- **Primary Test Suite:** `test_scanner.py`

## Core Components Tested
The testing focuses on the `PatternGenerator` class, which is critical for buffer overflow and format string vulnerability analysis.

### 1. Pattern Length Validation
Tests that the generator produces patterns of the exact requested length.
- **Test Case:** `test_create_length`
- **Result:** Pass (verified for lengths 0, 1, 10, 100, 1000)

### 2. Pattern Content & Uniqueness
Ensures the cyclic pattern follows the De Bruijn sequence-like logic (AAA, AAB, etc.) to allow for offset calculation.
- **Test Case:** `test_create_content`
- **Assertion:** `pattern[:3] == "AAA"` and `pattern[3:6] == "AAB"`

### 3. Offset Calculation
Verifies that the tool can correctly identify the exact position of a unique substring within a larger payload.
- **String Offset:** `test_offset_string` (Finds position of "AAA" or "AAB")
- **Integer Offset:** `test_offset_int` (Finds position based on memory addresses in little-endian format)

### 4. Error Handling
Ensures the tool gracefully handles cases where a pattern is not found.
- **Test Case:** `test_offset_not_found`
- **Result:** Returns `-1` instead of crashing.

## How to Run Tests
To execute the full test suite, run the following command from the project root:

```bash
python3 -m unittest tests/test_scanner.py
```

## Test Results Summary
| Test Case | Description | Result |
|-----------|-------------|--------|
| `test_create_length` | Verifies pattern output size | ✅ Pass |
| `test_create_content` | Verifies pattern generation logic | ✅ Pass |
| `test_create_unique_length` | Verifies unique pattern size | ✅ Pass |
| `test_offset_string` | Verifies string-based offset lookup | ✅ Pass |
| `test_offset_int` | Verifies address-based offset lookup | ✅ Pass |
| `test_offset_not_found` | Verifies handling of missing patterns | ✅ Pass |

## Manual Verification (Vulnerable Challenges)
To supplement unit testing, the scanner was manually verified against custom-built vulnerable programs.

### 1. Buffer Overflow (bof.c)
- **Goal:** Detect buffer overflow and calculate exact offset.
- **Verification:** Scanner successfully identified the vulnerability and calculated the correct offset of 72 bytes to overwrite the return address.
- **Result:** ✅ Successful exploit generation and shell access.

### 2. Format String (fmt.c)
- **Goal:** Identify format string vulnerability and leak memory.
- **Verification:** Scanner correctly identified the vulnerability at the input prompt and categorized leaked addresses (stack, code, etc.).
- **Result:** ✅ Successful memory leak and vulnerability identification.

## Future Testing Roadmap
To achieve 100% code coverage, future development will include:
1. **Mocking Subprocess:** Using `unittest.mock` to test `BinaryRunner` and `BinaryAnalyzer` without requiring actual Linux binaries.
2. **Integration Testing:** Testing the GUI's interaction with the underlying vulnerability scanner engine.
3. **Fuzzing Logic Tests:** Validating the smart test case generation logic in `IntelligentFuzzer`.

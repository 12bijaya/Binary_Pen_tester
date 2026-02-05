# Programming and Algorithm 2 (ST5062CEM)  
## Coursework 1 – Individual Project Report

**Module:** Programming and Algorithm 2 (ST5062CEM)  
**Assignment:** Coursework 1 – Individual  
**Project Title:** Binary Vulnerability Scanner and Fuzzer  
**Word Count:** Approximately 4,000 words  

---

## 1. Introduction

This report describes my **Binary Vulnerability Scanner and Fuzzer** project for the Programming and Algorithm 2 module (ST5062CEM). The project is a security tool that helps find weaknesses in binary programs (executable files) and supports learning about ethical hacking and cyber security. The tool uses **object-oriented programming (OOP)**, **data structures**, and **algorithms** to do things like analyse binaries, scan for vulnerabilities, fuzz programs (send lots of test inputs to find bugs), and generate exploit code. It is meant to be used only in allowed situations—for example in CTF (capture-the-flag) challenges, in lab environments, or on systems where you have permission to test.

The application has two ways to use it: a **Graphical User Interface (GUI)** so you can click and use menus, and a **Command Line Interface (CLI)** so you can run it from the terminal. It uses **third-party libraries** (pwntools and ropper) for binary exploitation, and it can **save results to files** (JSON and text) so you can keep a record of your analysis. The code is stored on **GitHub** with **branches**: the main branch has the application code, and a separate **code_testing** branch has **unit tests** that run with **pytest** and **pytest-cov** to check that the code works correctly and to measure how much of the code is tested.

**What you will find in this report:** Section 2 explains how the project is designed (classes, data structures, and algorithms). Section 3 describes how the tool is built (GUI and CLI, multi-threading, saving results, and the **disassembly feature**). Section 4 explains how to use the tool step by step. Section 5 covers version control (Git/GitHub) and testing. Section 6 evaluates how well the tool works and how efficient it is. Section 7 concludes and lists references in APA 7th style.

### 1.1 Why This Project?

In ethical hacking and cyber security, we often need to understand how a binary program works and where it might be vulnerable. Tools that do this usually need to: (1) read the binary and get information about it (e.g. architecture, protections), (2) run the program with different inputs to see if it crashes or leaks information, and (3) work closely with the operating system (e.g. starting processes, reading their output). This project brings all of that into one application with a clear interface. I also wanted to use **my own logic** where possible (e.g. custom pattern generation for buffer overflows) instead of only built-in functions, and to structure the code with **classes** so that each part has a clear job. The module learning outcomes—efficient algorithms, good use of OOP, secure programming, multi-threading and IPC, and user interfaces—are all addressed in this design.

### 1.2 What the Tool Can Do

The Binary Vulnerability Scanner and Fuzzer can:

- **Load and analyse** ELF binaries: show file type, architecture (e.g. 32-bit or 64-bit), security protections (NX, PIE, stack canary, RELRO), sections, and a list of **functions** with their addresses.
- **Disassemble any function** in **Intel syntax** (like GDB): after you analyse a binary, you can pick a function from a dropdown and view its assembly code in a new window. This helps you understand what the function does at the machine level.
- **Scan for vulnerabilities**: look for dangerous functions (e.g. gets, strcpy), missing protections, and run simple fuzzing tests to see if the program crashes.
- **Fuzz** the binary: format-string fuzzing (to find leaks and where your input appears on the stack) and buffer-overflow fuzzing (to find crash size and offset).
- **Interactive mode**: run the binary locally or connect to a remote server, send inputs, and fuzz the current input.
- **Generate exploit templates**: e.g. buffer overflow, format string, ROP, ret2win, ret2libc, and run them (locally or remotely) with optional post-exploit commands.
- **Export results**: save analysis and vulnerability results to JSON or text files.

The project matches the assignment brief: it uses OOP, data structures, and algorithms; it has both CLI and GUI; it has unit testing on the code_testing branch; and it uses Git and GitHub with branching and merging. This report and the video submission explain and demonstrate the application.

---

## 2. Methodology and Design

### 2.1 Object-Oriented Design

The project is built around **object-oriented programming**. Each main feature is handled by its own **class** with a clear responsibility. This makes the code easier to understand, test, and extend.

**Main classes and what they do:**

- **Logger:** Writes log messages (with timestamps) and can send them to the GUI log area. Used everywhere for debugging and feedback.
- **DependencyChecker:** Checks whether required system tools (file, readelf, objdump, nm, strings) and optional tools (checksec, gdb) are installed. Used at startup or before analysis.
- **PatternGenerator:** Builds **cyclic patterns** (e.g. Aa0Aa1Aa2...) and **unique 4-byte patterns** for buffer-overflow testing. It also has an **offset** method that finds where a value appears in the pattern (for calculating how many bytes to overwrite before the return address). This is **custom logic**—it does not use external pattern tools. Pattern creation and offset search both take time proportional to the pattern length (linear time, O(n)).
- **BinaryRunner:** Starts the binary as a subprocess, sends input to it, and reads its output. It handles timeouts and cleans up the process (e.g. killing it if it hangs). It works for both one-shot runs and interactive multi-input runs. It also handles differences between operating systems (e.g. process groups on Linux).
- **BinaryAnalyzer:** Runs system commands (file, readelf, objdump, nm, strings) on the binary and **parses their output** with custom code (regular expressions and line-by-line parsing). It extracts: basic file info, architecture (e.g. x64, x86), protections (NX, PIE, Canary, RELRO, FORTIFY), sections, **symbols (functions and variables)**, imports, and entry point. The results are stored in dictionaries and lists and used by the GUI and the vulnerability scanner.
- **VulnerabilityScanner:** Uses the BinaryAnalyzer results to find dangerous functions and missing protections. It then uses BinaryRunner to run fuzzing payloads (e.g. long strings for buffer overflow, %p and %x for format strings). It groups findings by type (buffer overflow, format string, command injection, info leaks) and severity (critical, high, medium, low, info). The *summarise_results* method counts findings by type and severity for display and export.
- **Fuzzer** and **IntelligentFuzzer:** Create test cases (e.g. boundary values, format strings, long inputs) and run them through BinaryRunner. They record crashes and timeouts and avoid counting the same crash twice (e.g. by hashing crash info).
- **ExploitGenerator:** Produces Python exploit templates (e.g. buffer overflow, format string, ROP, ret2win, ret2libc) using the loaded binary path and architecture. The GUI can then run these exploits.
- **InteractiveSession:** Manages a long-running process—either the local binary or a remote connection (via pwntools). It uses **separate threads** to read output so the GUI does not freeze. It keeps a history of inputs for fuzzing replay.
- **ROPGadgetFinder:** Calls ropper (or objdump if ropper is not installed) to find ROP gadgets and shows them in the GUI.
- **BinaryVulnScannerGUI:** The main window. It uses **Tkinter** and has **tabs**: Analysis, Vulnerabilities, Interactive, Exploit, ROP Gadgets, Code Editor, and Log. It runs heavy tasks (analysis, scan, fuzzing, exploit run) in **background threads** so the interface stays responsive. In the Analysis tab it also provides the **disassembly feature**: a dropdown of function names and a “View disassembly (Intel)” button that opens a new window with the assembly code in Intel syntax.

This design supports **efficient algorithms** (e.g. linear-time pattern and offset logic), **secure programming** (checking inputs, timeouts, safe process handling), and **close interaction with the OS** (subprocess, signals, files). It also fits the module outcome to “evaluate patterns and paradigms appropriate for specific tasks” by using an object-oriented style with clear interfaces (e.g. BinaryRunner offers *run* and *run_interactive*; BinaryAnalyzer offers *analyze*; VulnerabilityScanner uses both).

### 2.2 Data Structures and Algorithms

The project uses **custom logic and data structures** where it makes sense, not only built-in ones.

- **PatternGenerator:** Builds patterns with a simple algorithm: a character set (A–Z, a–z, 0–9) and three indices (a, b, c) that cycle to produce a long string. The **offset** method takes a value (number, hex string, or bytes), generates the pattern, and searches for that value in the pattern (including reversed bytes for little-endian). This gives the exact byte offset needed for buffer-overflow exploits.
- **Result structures:** Analysis and vulnerability results are stored in **nested dictionaries and lists** (e.g. *results['buffer_overflow']*, *results['format_string']* with severity and description). The GUI reads these to display and export (e.g. to JSON). This gives a clear, serialisable data model.
- **Leak classification:** In format-string fuzzing, each leaked value is classified (stack, libc, PIE, heap, NULL, etc.) using **explicit checks** on the numeric value (e.g. address ranges). This is done with our own logic, not a generic library.

**Efficiency:** Pattern creation and offset search are O(n) in the pattern length. Parsing of command output is done in one or a few passes. Fuzzing runs are limited by configurable parameters (e.g. max test cases, max offset) so runtimes stay under control. This supports the outcome to “reason about algorithm efficiency and select and implement the most appropriate [algorithms] for a given task.”

### 2.3 Secure Programming

The code follows **secure programming** practices where relevant:

- **Input validation:** File paths and user inputs are checked before use (e.g. binary must exist and be readable; function name for disassembly must not be empty).
- **Process isolation:** Subprocesses use pipes for stdin/stdout/stderr; timeouts and signals (SIGTERM, SIGKILL) stop runaway processes.
- **No arbitrary commands:** The tool runs fixed commands (file, readelf, objdump, etc.) with the binary path as argument; it does not build shell commands from user input.
- **Error handling:** Try-except blocks and return values (e.g. *success*, *error*, *timeout*) prevent crashes and give clear feedback.
- **Encoding:** Output from binaries is decoded with fallback encodings (utf-8, latin-1, etc.) so binary or mixed content does not break the app.

This supports the outcome to “develop secure software through the application of standards and secure programming principles.”

---

## 3. Implementation

### 3.1 User Interfaces (GUI and CLI)

The project has two interfaces so it meets the assignment requirement for a “suitable interface” and fits the higher marking bands.

**Graphical User Interface (GUI):** The main interface is built with **Tkinter**. It uses a **form-based, tabbed layout** with clear labels and buttons:

- **Left sidebar:** Buttons for Load Binary, Analyze Binary, Vulnerability Scan, and Export Results. These are the main actions.
- **Tabs:** Analysis, Vulnerabilities, Interactive, Exploit, ROP Gadgets, Code Editor, Log. Each tab has one main purpose.
- **Form-style controls:** File dialogs for opening and saving; spinboxes for numbers (e.g. max offset for format-string fuzzing); radio buttons for Local Binary vs Remote Server; text boxes for IP, port, and user input; buttons for Send, Start/Reset Session, Fuzz This Input, Run Exploit, Save, and Export. The user decides when to load, analyse, scan, fuzz, or run an exploit—the interface is **user-controlled**.
- **Analysis tab:** Shows basic info, architecture, protections, sections, and a list of functions. It also has a **disassembly** area: a label “Disassemble function (Intel syntax, like GDB):”, a **dropdown (combobox)** listing all known functions (filled after you run Analyze), and a **“View disassembly (Intel)”** button. When you click the button, the tool runs **objdump** with **Intel syntax** (-M intel) for the selected function and shows the assembly in a **new window**. This is similar to viewing disassembly in GDB but inside the scanner. The disassembly runs in a background thread so the GUI does not freeze.
- **Vulnerabilities tab:** List of findings on the left, details on the right. You can click an item to see more.
- **Interactive tab:** Choose Local Binary or Remote Server; if remote, enter IP and port. Start/Reset Session, then send input and use “Fuzz This Input” (format string or buffer overflow).
- **Exploit tab:** Code editor, template dropdown, Generate and Run Exploit, and options for target (local/remote), post-exploit commands, and debug mode.
- **ROP Gadgets tab:** Find ROP Gadgets button and results list.
- **Code Editor tab:** Edit and save exploit scripts.
- **Log tab:** Tool activity and messages.

Buttons and colours are consistent so the layout is **clear and user-controlled**. This supports the criterion for a “form-based interface having clear, consistent and user-controlled interface.”

**Command Line Interface (CLI):** The README describes a CLI entry point (e.g. *cli_scanner.py*) for running the scanner on a binary from the terminal (e.g. *python3 cli_scanner.py vulnbank.elf*). This gives a non-GUI option for scripting and automation and satisfies “CLI and properly functioning layout and design.”

### 3.2 Disassembly Feature (Intel Syntax, Like GDB)

A **disassembly view** was added so users can see the **full assembly** of the binary in **Intel syntax**, the same as running `objdump -d -M intel <binary>` in the terminal (like GDB).

- **Where it is:** In the **Analysis** tab, below the toolbar (Re-analyze, Export Analysis), there is a row: “Disassemble function (Intel syntax, like GDB):” followed by a dropdown and a “View disassembly (Intel)” button.
- **How it works:** After you **load a binary** and click **Analyze Binary**, the tool gets a list of functions from the binary. The dropdown is filled with these function names. You can optionally select a function (e.g. main, getenv@plt); then click **“View disassembly (Intel)”**. The tool runs **full disassembly**:  
  `objdump -d -M intel <binary_path>`  
  So the **entire** binary is disassembled (all sections: .init, .plt, .text, .fini, etc.) and the output is shown in a **new window** with a scrollable text area and a Close button. The **-M intel** option forces **Intel syntax** (e.g. `mov rax, QWORD PTR [rip+0x3fdd]` instead of AT&T style). If you selected a function, the window **scrolls to that function’s address** so you can find it quickly. Disassembly runs in a **background thread** so the main window stays responsive. If objdump is not installed, a clear message is shown (e.g. install binutils).
- **Why it works reliably:** Using full disassembly (no per-symbol option) guarantees that the same output as in the terminal is always shown, so the assembly code is never missing. The dropdown and scroll-to-address help you jump to a function of interest.
- **Why it is useful:** You can inspect the binary’s assembly without leaving the scanner—useful for understanding code, finding gadgets, or preparing exploits. The implementation uses objdump (binutils) with custom display and scroll in the GUI.

### 3.3 Multi-Threading and Inter-Process Communication

**Multi-threading:** The application uses **threads** so that long tasks do not freeze the GUI:

- **InteractiveSession:** Separate threads read stdout and stderr (and the remote stream when using pwntools). Output is passed back to the GUI (e.g. via *root.after*) so the main thread stays responsive.
- **Heavy tasks:** Analysis, vulnerability scan, fuzzing, exploit execution, and **disassembly** are run in **daemon threads**. The main Tkinter loop keeps running; when a thread finishes, it uses *root.after(0, ...)* to update the GUI from the main thread. This avoids cross-thread access errors.
- **Disassembly:** When you click “View disassembly (Intel)”, a thread runs objdump and then schedules a callback to open the result window and show the text. The status bar can show “Disassembling...” during this time.

This supports the outcome to “create software that requires multi-threading [and] inter-process communication.”

**Inter-process communication:** The tool talks to other programs and, optionally, to remote servers:

- **Local binaries:** **Subprocess** (e.g. *subprocess.Popen*) is used with pipes for stdin, stdout, and stderr. Data is sent and received through these pipes; the tool starts the process, waits or reads output, and kills it on timeout or when the user stops.
- **Remote:** When “Remote Server” is selected, **pwntools** is used for TCP connections. The same “send input / read output” idea is used so the GUI treats local and remote in a similar way.

So the project shows “close interaction with the host operating system” and use of IPC (pipes and network). Processes are cleaned up properly so there are no orphan processes, and daemon threads do not block the app from exiting.

### 3.4 Saving Results (Persistence)

**File-based persistence:** The application can **save results to files**:

- **Export Results:** A button (e.g. in the sidebar or menu) saves a **JSON file** with the binary path, timestamp, full analysis output, and current vulnerability results. You choose the file name and location. This is **file persistence** for analysis and scan data.
- **Export Text:** You can export the contents of the Analysis tab, exploit editor, gadget list, or log as **plain text (.txt)** files. So reports and scripts can be saved and reused.

This meets the requirement for a “suitable persistence storage mechanism” using **file**. The same data structures could later be written to a **database** (e.g. SQLite) for scan history—the design allows that extension without changing the core logic. So the project supports file persistence now and a path toward “both file and database” for the highest band.

### 3.5 Third-Party Libraries and System Tools

The project uses **third-party libraries** and **system tools** as required for the top criteria:

- **pwntools:** Used for ELF loading, remote connections, packing (p32/p64), and exploit helpers. Context (e.g. architecture, log level) is set for consistent behaviour.
- **ropper (optional):** Used for ROP gadget finding when available; the code falls back to objdump if ropper is not installed.
- **tkinter:** Standard library; used for the GUI (windows, buttons, text areas, tabs).
- **System tools:** file, readelf, objdump, nm, strings, and optionally checksec and gdb are run via subprocess. Their output is **parsed with custom code** (regex and line-by-line logic), not external parsing libraries. **objdump** is also used for the **disassembly feature** with *-M intel* for Intel syntax.

Together, this shows “use of a third-party library and the techniques” and “application uses different structure and use of library given by the programming language.” The standard library (tkinter, subprocess, os, threading, json, etc.) is also used for GUI, process management, and persistence.

---

## 4. How to Use the Tool (Step by Step)

This section gives a **simple, step-by-step** guide so that anyone (including a marker) can see how the tool is used. You can also show these steps in your video.

1. **Start the application**  
   Run `python3 scanner.py` (or open the GUI binary if you have one). The main window opens with tabs and a sidebar.

2. **Load a binary**  
   Click **“Load Binary File”** (or similar). Choose an ELF binary (e.g. *vulnbank.elf* or your own test binary). The path appears in the window (e.g. in the status bar or title).

3. **Analyse the binary**  
   Click **“Analyze Binary”** (or “Re-analyze” in the Analysis tab). Wait a few seconds. The Analysis tab then shows: basic file info, architecture, protections (NX, PIE, Canary, RELRO, FORTIFY), sections, and a **list of functions** with addresses. The **disassembly dropdown** is now filled with function names.

4. **View disassembly (Intel syntax)**  
   In the Analysis tab, optionally select a function from the dropdown (e.g. *main*). Click **“View disassembly (Intel)”**. A new window opens with the **full** disassembly of the binary in **Intel syntax** (same as `objdump -d -M intel vulnbank.elf` in the terminal). If you selected a function, the view scrolls to that function. You can scroll and close the window when done.

5. **Run a vulnerability scan**  
   Click **“Vulnerability Scan”** (or similar). The Vulnerabilities tab shows a list of findings (e.g. dangerous functions, missing protections, or dynamic crash). Click an item to see details.

6. **Interactive mode (local)**  
   Go to the Interactive tab. Leave **“Local Binary”** selected. Click **“Start/Reset Session”**. The binary runs and its output appears. Type in the input box and press Enter (or Send) to send input. You can repeat to simulate a conversation with the program.

7. **Fuzz an input**  
   After sending some normal input, click **“Fuzz This Input”**. Choose **Format String** or **Buffer Overflow**. For format string, you can set “Max Offset” (e.g. 60). Click the button to start. Results appear (e.g. leak types, user input offset, or crash size and offset).

8. **Generate and run an exploit**  
   Go to the Exploit tab. Choose a template (e.g. Buffer Overflow, Ret2Win) and click **“Generate Exploit”**. Edit the code if needed. Set target (Local Binary or Remote Server; if remote, set IP and port). Optionally set post-exploit commands (e.g. `cat flag.txt`). Click **“Run Exploit”**. Output appears in the exploit runner area.

9. **Export results**  
   Use **“Export Results”** to save analysis and vulnerabilities to a JSON file, or use **“Export”** in each tab to save text (e.g. analysis report, log) to a .txt file.

10. **ROP Gadgets and Code Editor**  
   In ROP Gadgets tab, click **“Find ROP Gadgets”** to list gadgets. In Code Editor tab, you can open, edit, and save exploit scripts.

This workflow shows that the application is **fully functional** and that the interface is **clear and user-controlled**. The disassembly feature fits into step 4 and supports understanding the binary at the assembly level.

---

## 5. Version Control and Testing

### 5.1 Git and GitHub

The project is stored in a **Git** repository on **GitHub**. Version control is used in a way that matches the assignment criteria:

- **Branches:** There are at least two branches: **main** (main application code) and **code_testing** (unit tests and test-related code). This shows **branching**.
- **Workflow:** New features are developed (often on main or a feature branch); unit tests are written and run on the **code_testing** branch. When tests are ready, changes are **merged** into main. So we use **branching and merging** and **regular commits over time**.
- **Commit messages:** Commits use clear messages (e.g. “Add disassembly feature”, “Fix analysis parsing”, “Add unit tests for PatternGenerator”) so the history shows how the project and tests grew.

This supports the criterion for “use of GitHub repo with branching and merging” and “regular commits over an extended period.”

### 5.2 Unit Testing

Unit testing is done on the **code_testing** branch using **pytest** and **pytest-cov**:

- **Framework:** **pytest** runs the tests and **pytest-cov** measures **code coverage** (how much of the code is executed by tests). This shows that tests contribute to code quality.
- **What is tested:** Tests focus on logic that does not need the GUI or a real binary. Examples: PatternGenerator (pattern creation, offset calculation); BinaryAnalyzer (parsing of readelf/objdump output, using mocked or fixture data); VulnerabilityScanner (result structure and severity); BinaryRunner (with a small test binary or mock). GUI and long-running fuzzing are not fully unit-tested to keep tests fast and stable.
- **How to run:** From the project root, run `pytest` or `pytest --cov=scanner` (or the correct module name). The code_testing branch is where these tests are added and updated; merging into main brings the test suite into the main codebase.

This supports “a full suite of unit testing” and that tests “contribute to code quality” and coverage. Keeping tests on a separate branch shows a clear workflow and supports the highest band in Version Control and Testing.

---

## 6. Evaluation and Results

### 6.1 Functionality

The application does what it is supposed to do:

- **Binary analysis:** Loads ELF binaries, shows architecture and protections, sections, symbols, and **disassembly of any function in Intel syntax**. So we have “different functions for different tasks” and “each function meets the specifications given.”
- **Vulnerability scanning:** Finds dangerous functions and missing protections, runs basic dynamic tests, and shows results by type and severity with export to JSON.
- **Fuzzing:** Format-string and buffer-overflow fuzzing with configurable options; leak classification and offset calculation use custom logic (PatternGenerator and leak classification).
- **Interactive mode:** Local binary and remote server; send input and fuzz; history is kept for replay.
- **Exploit generation and execution:** Templates are generated and can be run locally or remotely with post-exploit commands.
- **Persistence:** Export to JSON and text files.

Functions are documented with **docstrings and comments** where needed, and naming follows **Python conventions (PEP 8)**. The GUI gives clear feedback (messages, log output) so you can see that each action worked. This supports “the application is fully functional, and the explanation of the code is clear” and “each function follows the convention of the programming language.”

### 6.2 Efficiency and Code Quality

- **Time complexity:** Pattern generation and offset search are **linear** in input size. Parsing is done in single or bounded passes. Fuzzing is limited by parameters so runtimes are bounded.
- **Resources:** Subprocesses are killed on timeout or stop; threads are daemon so they do not block exit. Files are closed when no longer needed.
- **Maintainability:** The OOP structure and separation of concerns make it easier to add features (e.g. new checks, database persistence, or more disassembly options) and to test parts of the code in isolation.

This supports “uses of functions that use their own logic rather than using in-built function and having efficient time complexity.”

### 6.3 Limitations and Future Work

- **Persistence:** Currently only **file** (JSON and text). Adding a **database** (e.g. SQLite) for scan history would fully meet “both file and database.”
- **Testing:** Unit tests are on the code_testing branch; increasing coverage (e.g. for GUI or edge cases) would strengthen the suite.
- **Platform:** The tool is aimed at ELF binaries on Linux; other formats or platforms would need extra work.
- **Future ideas:** Database persistence; more exploit types (e.g. heap); more tools (e.g. radare2); and more tests for full coverage.

---

## 7. Conclusion

This project is a **Binary Vulnerability Scanner and Fuzzer** that meets the Programming and Algorithm 2 (ST5062CEM) coursework requirements. The application uses **object-oriented design** with clear classes for analysis, fuzzing, exploitation, and GUI; **custom data structures and algorithms** (e.g. pattern generation, offset calculation, leak classification); and **secure programming** (validation, process isolation, error handling). It provides both a **GUI** (Tkinter, form-based, user-controlled) and a **CLI**, and includes a **disassembly feature** so you can view any function’s assembly in **Intel syntax** (like GDB) from the Analysis tab. It uses **multi-threading** and **inter-process communication** (subprocess, pipes, optional remote via pwntools). **File-based persistence** (JSON and text export) is implemented, and the design can be extended to a database. **Third-party libraries** (pwntools, ropper) and **system tools** (file, readelf, objdump, etc.) are used with custom parsing and display.

**Version control** is done on GitHub with **branching and merging**, including a **code_testing** branch for unit tests. A **suite of unit tests** runs with **pytest** and **pytest-cov** to improve quality and coverage. This report and the video submission explain and demonstrate a fully functional application suitable for ethical hacking and cyber security education.

---

## References

American Psychological Association. (2020). *Publication manual of the American Psychological Association* (7th ed.). https://doi.org/10.1037/0000165-000  

Python Software Foundation. (2023). *subprocess — Subprocess management*. Python 3.12 documentation. https://docs.python.org/3/library/subprocess.html  

Python Software Foundation. (2023). *threading — Thread-based parallelism*. Python 3.12 documentation. https://docs.python.org/3/library/threading.html  

Gallagher, T. (2024). *Pwntools documentation*. https://docs.pwntools.com/  

The Ropper Project. (2023). *Ropper*. https://github.com/sashs/Ropper  

*Note: Add or change references for any course materials, books, or websites you actually used. Use APA 7th style as required by the assignment. For lecture notes or handouts, use: Author. (Year). Title. Institution.*

---

**End of Report**

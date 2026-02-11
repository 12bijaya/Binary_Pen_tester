# Version Control Documentation

## Overview
This project utilizes **Git** for version control and **GitHub** for repository hosting and collaboration. The use of version control was essential for tracking changes, experimenting with new features through branching, and maintaining a stable codebase throughout the development process.

## Repository Details
- **Platform:** GitHub
- **Repository Name:** `Binary_Pen_tester`
- **Username:** `12bijaya`
- **Main Branch:** `main`
- **Development Branch:** `code_testing`

## Branching Strategy
A feature-based branching strategy was implemented to ensure code stability:
- **`main` Branch:** Stores the production-ready code. Only tested and verified features are merged here.
- **`code_testing` Branch:** Used for implementing and testing new features such as the binary disassembly module and unit testing framework before they are finalized.

## Commit Frequency and Consistency
The project maintain regular commits over the development period. Commits are categorized by their purpose:
- **Feature Addition:** Commits like `Added some feature` and `Binary disassembly feature updated` show the evolution of the tool.
- **Maintenance:** Commits like `Apply .gitignore` and `Apply .gitignore fix` show attention to repository hygiene.
- **Testing:** Specific commits for unit testing (`Unit testing`) demonstrate a commitment to code quality.

## Commit History Snippet
| Date | Hash | Message |
|------|------|---------|
| 2026-02-11 | `0ec9516` | Add vulnerable challenges and update ignore rules |
| 2026-02-11 | `7fb0d92` | Unit testing |
| 2026-02-10 | `4f7abd4` | Binary disassembly feature updated... |
| 2026-02-09 | `8d734d1` | Binary pentester completed |

## Summary of Version Control Benefits
1. **Traceability:** Ability to revert to previous working states if a new feature introduced bugs.
2. **Experimental Development:** Using the `code_testing` branch allowed for risky changes without breaking the main application.
3. **Documentation:** The commit log serves as a chronological record of the project's growth.

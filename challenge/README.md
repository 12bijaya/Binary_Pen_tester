# Vulnerable Challenge Testing Guide

This directory contains a sample `ret2win` challenge designed to test the features of the **Binary Vulnerability Scanner**.

## Vulnerabilities Included
1.  **Format String (`printf(name)`):** Located in the "Enter your name" prompt. Can be used to leak memory addresses from the stack.
2.  **Buffer Overflow (`gets(buffer)`):** Located in the "Enter a secret message" prompt. Since `gets()` is used on a 64-byte buffer without bounds checking, it allows for stack smashing and return address redirection.

## Compilation for Local Testing
To compile the binaries locally for the scanner to analyze, run:
```bash
gcc -o bof bof.c -fno-stack-protector -z execstack -no-pie -fno-pie
gcc -o fmt fmt.c -fno-stack-protector -z execstack -no-pie -fno-pie
```

## Running with Docker
The provided Dockerfile allows you to host this challenge as a remote service (similar to a CTF).

1.  **Build the image:**
    ```bash
    docker build -t pwn-challenge .
    ```
2.  **Run the container:**
    ```bash
    docker run -d -p 1337:1337 --name test-challenge pwn-challenge
    ```
3.  **Connect and Test:**
    You can now point the `scanner.py` tool to `127.0.0.1:1337` using the "Remote Session" feature.

## Exploit Goal
The objective is to find the address of the `win()` function (e.g., using the scanner's disassembly or `nm challenge`) and overwrite the return address on the stack during the buffer overflow prompt to jump to `win()`.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void shell() {
    system("/bin/sh");
}

void vuln() {
    char buffer[64];
    printf("Enter data: ");
    gets(buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("Buffer Overflow Challenge\n");
    vuln();
    return 0;
}

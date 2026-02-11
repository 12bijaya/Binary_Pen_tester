#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void shell() {
    system("/bin/sh");
}

void vuln() {
    char buffer[128];
    printf("Enter string: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) return;
    printf(buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("Format String Challenge\n");
    while(1) {
        vuln();
        printf("\n");
    }
    return 0;
}

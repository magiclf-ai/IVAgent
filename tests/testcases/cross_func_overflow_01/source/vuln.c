#include <stdio.h>
#include <string.h>

void copy_data(const char *src) {
    char dest[64];
    strcpy(dest, src);
    printf("Copied: %s\n", dest);
}

void handle_request(const char *input) {
    copy_data(input);
}

int main(void) {
    char malicious_input[256];
    memset(malicious_input, 'A', sizeof(malicious_input));
    malicious_input[255] = '\0';
    handle_request(malicious_input);
    return 0;
}

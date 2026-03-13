#include <stdio.h>
#include <string.h>

void log_message(const char *msg) {
    printf(msg);
    printf("\n");
}

int main(void) {
    char user_input[256];
    strcpy(user_input, "%x %x %x %x %s");
    log_message(user_input);
    return 0;
}

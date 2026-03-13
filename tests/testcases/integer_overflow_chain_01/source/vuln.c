#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int calculate_size(int count, int item_size) {
    return count * item_size;
}

void allocate_and_copy(const char *data, int count, int item_size) {
    int total_size = calculate_size(count, item_size);
    char *buffer = (char *)malloc(total_size);
    if (!buffer) {
        return;
    }

    memcpy(buffer, data, count * item_size);
    printf("Copied data into %d-byte allocation\n", total_size);
    free(buffer);
}

int main(void) {
    char large_data[1024];
    memset(large_data, 'A', sizeof(large_data));
    allocate_and_copy(large_data, 0x40000000, 4);
    return 0;
}

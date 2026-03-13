#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    int size;
} Buffer;

Buffer *global_buf = NULL;

void free_buffer(void) {
    if (global_buf) {
        free(global_buf->data);
        free(global_buf);
    }
}

void use_buffer(void) {
    if (global_buf) {
        memset(global_buf->data, 0, global_buf->size);
        printf("Buffer used\n");
    }
}

void process_data(const char *input, int len) {
    global_buf = (Buffer *)malloc(sizeof(Buffer));
    if (!global_buf) {
        return;
    }
    global_buf->data = (char *)malloc(len);
    if (!global_buf->data) {
        free(global_buf);
        global_buf = NULL;
        return;
    }

    global_buf->size = len;
    memcpy(global_buf->data, input, len);
    free_buffer();
    use_buffer();
}

int main(void) {
    char data[] = "test data";
    process_data(data, sizeof(data));
    return 0;
}

#include <stdlib.h>
#include <string.h>

typedef struct {
    char buffer[64];
    int size;
} Packet;

void parse_packet(const char *data, int len) {
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) {
        return;
    }

    memcpy(pkt->buffer, data, len);
    pkt->size = len;
    free(pkt);
}

int main(void) {
    char malicious_data[128];
    memset(malicious_data, 'A', sizeof(malicious_data));
    parse_packet(malicious_data, 128);
    return 0;
}

#include "edge_mqtt_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int run_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open input: %s\n", path);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65536) {
        fclose(f);
        return 1;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 2;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    agx2_packet_t pkt;
    int rc = parse_edge_mqtt_packet(buf, n, &pkt);
    free(buf);
    return rc == 0 ? 0 : 1;
}

static int run_bounded_refuzz(int iterations) {
    srand(1337);
    uint8_t buf[512];
    agx2_packet_t pkt;
    for (int i = 0; i < iterations; i++) {
        size_t payload_len = (size_t)(rand() % 300);
        size_t topic_len = 1 + (size_t)(rand() % 12);
        size_t total = 8 + topic_len + payload_len + 1;
        if (total > sizeof(buf)) continue;

        buf[0] = 'A'; buf[1] = 'G'; buf[2] = 'X'; buf[3] = '2';
        buf[4] = (uint8_t)(rand() % 4);
        buf[5] = (uint8_t)topic_len;
        buf[6] = (uint8_t)((payload_len >> 8) & 0xFF);
        buf[7] = (uint8_t)(payload_len & 0xFF);
        for (size_t j = 0; j < topic_len; j++) {
            buf[8 + j] = (uint8_t)('a' + (rand() % 26));
        }
        for (size_t j = 0; j < payload_len; j++) {
            buf[8 + topic_len + j] = (uint8_t)(rand() & 0xFF);
        }
        /* 80% valid CRC, 20% mutated CRC */
        uint8_t crc = agx2_xor_crc(buf, total - 1);
        buf[total - 1] = (i % 5 == 0) ? (uint8_t)(crc ^ 0xFF) : crc;

        (void)parse_edge_mqtt_packet(buf, total, &pkt);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--refuzz") == 0) {
        int iters = atoi(argv[2]);
        return run_bounded_refuzz(iters > 0 ? iters : 5000);
    }
    if (argc == 2) {
        return run_file(argv[1]);
    }
    fprintf(stderr, "Usage: %s <seed_file> | --refuzz <N>\n", argv[0]);
    return 2;
}

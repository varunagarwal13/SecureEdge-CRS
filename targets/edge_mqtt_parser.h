#ifndef EDGE_MQTT_PARSER_H
#define EDGE_MQTT_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define AGX2_MAGIC_0 'A'
#define AGX2_MAGIC_1 'G'
#define AGX2_MAGIC_2 'X'
#define AGX2_MAGIC_3 '2'
#define AGX2_MAX_PAYLOAD 256

typedef struct {
    uint8_t msg_type;
    uint16_t declared_len;
    uint16_t actual_len;
    char topic[32];
    uint8_t payload[AGX2_MAX_PAYLOAD];
} agx2_packet_t;

uint8_t agx2_xor_crc(const uint8_t *buf, size_t len);
int parse_edge_mqtt_packet(const uint8_t *data, size_t len, agx2_packet_t *out);

#endif

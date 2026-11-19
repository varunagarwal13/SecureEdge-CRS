#include "edge_mqtt_parser.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t build_pkt(uint8_t *buf, uint8_t msg_type, const char *topic,
                        const uint8_t *payload, uint16_t payload_len) {
    uint8_t tlen = (uint8_t)strlen(topic);
    buf[0] = 'A'; buf[1] = 'G'; buf[2] = 'X'; buf[3] = '2';
    buf[4] = msg_type;
    buf[5] = tlen;
    buf[6] = (uint8_t)((payload_len >> 8) & 0xFF);
    buf[7] = (uint8_t)(payload_len & 0xFF);
    memcpy(buf + 8, topic, tlen);
    if (payload_len > 0 && payload) {
        memcpy(buf + 8 + tlen, payload, payload_len);
    }
    size_t body_len = 8 + tlen + payload_len;
    buf[body_len] = agx2_xor_crc(buf, body_len);
    return body_len + 1;
}

int main(void) {
    uint8_t buf[512];
    agx2_packet_t pkt;

    /* T1: Valid short telemetry packet */
    const uint8_t p1[] = "temp=24.5C";
    size_t n = build_pkt(buf, 1, "sensor/t1", p1, (uint16_t)strlen((const char *)p1));
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == 0);
    assert(pkt.msg_type == 1);
    assert(strcmp(pkt.topic, "sensor/t1") == 0);
    assert(pkt.actual_len == strlen((const char *)p1));
    assert(memcmp(pkt.payload, p1, pkt.actual_len) == 0);

    /* T2: Valid empty payload */
    n = build_pkt(buf, 2, "ping", NULL, 0);
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == 0);
    assert(pkt.actual_len == 0);

    /* T3: Invalid magic header rejected */
    n = build_pkt(buf, 1, "sensor/t1", p1, 4);
    buf[0] = 'X';
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == -2);

    /* T4: Corrupted XOR-CRC rejected */
    n = build_pkt(buf, 1, "sensor/t1", p1, 4);
    buf[n - 1] ^= 0x01;
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == -3);

    /* T5: Truncated input rejected */
    assert(parse_edge_mqtt_packet(buf, 4, &pkt) == -1);

    /* T6: Null pointer safety */
    assert(parse_edge_mqtt_packet(NULL, 16, &pkt) == -1);
    assert(parse_edge_mqtt_packet(buf, 16, NULL) == -1);

    /* T7: Zero-length topic rejected */
    n = build_pkt(buf, 1, "", p1, 4);
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == -4);

    /* T8: Oversized topic rejected */
    n = build_pkt(buf, 1, "this_topic_name_is_far_too_long_for_32_bytes", p1, 4);
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == -4);

    /* T9: Declared length exceeds actual buffer rejected */
    n = build_pkt(buf, 1, "ok", p1, 4);
    buf[7] = 99;
    buf[n - 1] = agx2_xor_crc(buf, n - 1);
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == -5);

    /* T10: Valid 200-byte binary payload preserved intact */
    uint8_t p10[200];
    for (int i = 0; i < 200; i++) p10[i] = (uint8_t)(i & 0xFF);
    n = build_pkt(buf, 3, "plc/telemetry", p10, 200);
    assert(parse_edge_mqtt_packet(buf, n, &pkt) == 0);
    assert(pkt.actual_len == 200);
    assert(memcmp(pkt.payload, p10, 200) == 0);

    printf("PASS: 10/10 functional tests succeeded\n");
    return 0;
}

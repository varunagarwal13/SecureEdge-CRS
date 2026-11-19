#include "edge_mqtt_parser.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    agx2_packet_t pkt;
    (void)parse_edge_mqtt_packet(data, size, &pkt);
    return 0;
}

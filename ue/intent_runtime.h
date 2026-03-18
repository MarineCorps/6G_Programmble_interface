#ifndef INTENT_RUNTIME_H
#define INTENT_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "intent_pkt.h"

typedef struct {
    uint8_t  l4_proto;
    uint32_t dst_ip_be;
    uint16_t dst_port_be;
    uint16_t src_port_be;
    uint32_t payload_len;
    int      sock_type;
    int      fd;
} flow_meta_t;

int intent_runtime_init(void);
void intent_runtime_fini(void);

int extract_flow_meta_from_fd(int fd, size_t payload_len, flow_meta_t *out);

int build_intent_packet(const flow_meta_t *fm,
                        uint8_t phase,
                        uint8_t confidence,
                        uint16_t eta_ms,
                        uint32_t expected_bytes,
                        uint32_t deadline_us,
                        uint8_t *buf,
                        size_t buf_sz,
                        size_t *out_len);

int send_intent_packet(const uint8_t *buf, size_t len);

uint32_t make_session_id(void);

int is_intent_sockfd(int fd);

#endif /* INTENT_RUNTIME_H */
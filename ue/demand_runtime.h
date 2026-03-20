#ifndef DEMAND_RUNTIME_H
#define DEMAND_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "demand_pkt.h"

typedef struct {
    uint8_t  l4_proto;
    uint32_t dst_ip_be;
    uint16_t dst_port_be;
    uint16_t src_port_be;
    uint32_t payload_len;
    int      sock_type;
    int      fd;
} flow_meta_t;

int  demand_runtime_init(void);
void demand_runtime_fini(void);

int is_demand_sockfd(int fd);

int extract_flow_meta_from_fd(int fd, size_t payload_len, flow_meta_t *out);

int build_6g_information(const flow_meta_t *fm,
                         uint8_t           app_type,
                         uint32_t          payload_bytes,
                         uint16_t          deadline_ms,
                         uint8_t          *buf,
                         size_t            buf_sz,
                         size_t           *out_len);

int send_demand_packet(const uint8_t *buf, size_t len);

#endif /* DEMAND_RUNTIME_H */

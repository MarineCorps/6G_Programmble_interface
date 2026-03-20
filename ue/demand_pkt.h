#ifndef DEMAND_PKT_H
#define DEMAND_PKT_H

#include <stdint.h>

/*
 * protocol_id: UDP payload 맨 앞에서 이 패킷이
 * 6G Demand API 프로토콜임을 식별하는 4바이트 서명.
 * ASCII '6','G','N','I' = 0x36474E49
 */
#define DEMAND6_PROTOCOL_ID  0x36474E49u
#define DEMAND6_VERSION      1
#define DEMAND6_DST_PORT     48888

typedef enum __attribute__((packed)) {
    APP_UNKNOWN = 0,  /* fallback → 기존 BSR 처리          */
    APP_LLM     = 1,  /* LLM 토큰 스트리밍                  */
    APP_VLA     = 2,  /* Vision-Language-Action 프레임      */
    APP_VIDEO   = 3,  /* 실시간 영상                        */
    APP_BULK    = 4,  /* 대용량 전송 (Best Effort)          */
} app_type_t;

typedef struct __attribute__((packed)) {
    uint32_t protocol_id;    /* +0   '6GNI' — 프로토콜 식별자  (4B) */
    uint8_t  app_type;       /* +4   app_type_t                 (1B) */
    uint8_t  _reserved;      /* +5   향후 확장 예약, 항상 0     (1B) */
    uint16_t src_port;       /* +6   flow 식별자, network order (2B) */
    uint32_t payload_bytes;  /* +8   예상 전송량, network order (4B) */
    uint16_t deadline_ms;    /* +12  soft deadline, 0=없음      (2B) */
    uint16_t _pad;           /* +14  정렬 패딩, 항상 0          (2B) */
} demand6_t;                 /* 총 16 bytes                          */

#endif /* DEMAND_PKT_H */

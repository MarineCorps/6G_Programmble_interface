#ifndef INTENT_PKT_H
#define INTENT_PKT_H

#include <stdint.h>

/*
 * __attribute__((packed)):
 * 구조체 멤버 사이에 padding 삽입을 금지.
 * 메모리 배치 = wire format 이 되어야 하므로 필수.
 */

#define INTENT_MAGIC    0x494E5450u  /* ASCII: 'I','N','T','P' */
#define INTENT_VERSION  1
#define INTENT_DST_PORT 48888        /* gNB가 listen할 well-known port */

/* ── msg_type ─────────────────────────────────────────────────── */
enum intent_msg_type {
    INTENT_MSG_DECLARE  = 1,   /* 곧 전송 예정 */
    INTENT_MSG_UPDATE   = 2,   /* 예측치 수정  */
    INTENT_MSG_COMPLETE = 3,   /* 전송 완료    */
};

/* ── phase ────────────────────────────────────────────────────── */
enum intent_phase {
    INTENT_PHASE_UNKNOWN  = 0,
    INTENT_PHASE_PRE_TX   = 1,   /* 전송 직전 준비 단계 */
    INTENT_PHASE_TX_BURST = 2,   /* burst 전송 중       */
    INTENT_PHASE_STREAM   = 3,   /* 연속 스트리밍       */
};

/* ── 공통 헤더 (8 bytes) ──────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t magic;      /* INTENT_MAGIC                     */
    uint8_t  version;    /* INTENT_VERSION                   */
    uint8_t  msg_type;   /* intent_msg_type                  */
    uint16_t total_len;  /* 전체 패킷 길이 (network order)   */
} intent_hdr_t;

/* ── flow 바인딩 (16 bytes) ──────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  l4_proto;           /* IPPROTO_UDP / IPPROTO_TCP         */
    uint8_t  reserved0;          /* 향후 확장 예약                    */
    uint16_t reserved1;          /* 향후 확장 예약                    */

    uint32_t original_dst_ip;    /* 원래 data flow 의 dst IPv4        */
    uint16_t original_dst_port;  /* 원래 data flow 의 dst port        */
    uint16_t original_src_port;  /* 원래 data flow 의 src port        */

    uint32_t session_id;         /* 프로세스 단위 세션 식별자         */
    uint32_t intent_id;          /* 메시지 단위 intent 식별자         */
} flow_bind_t;

/* ── hint 본문 (12 bytes) ────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  phase;            /* intent_phase                      */
    uint8_t  confidence;       /* 0-100 (100 = 100% 확신)           */
    uint16_t eta_ms;           /* 실제 데이터까지 예상 지연 (ms)    */
    uint32_t expected_bytes;   /* 예상 전송량 (bytes)               */
    uint32_t deadline_us;      /* soft deadline (us, 0 = 없음)      */
} hint_body_t;

/* ── 전체 패킷 (36 bytes) ────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    intent_hdr_t hdr;
    flow_bind_t  bind;
    hint_body_t  hint;
} intent_pkt_t;

#endif /* INTENT_PKT_H */

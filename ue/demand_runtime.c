#define _GNU_SOURCE

#include "demand_runtime.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ── 전역 변수 ──────────────────────────────────────────────────
 * demand 메시지를 보내는 데 사용될 UDP 소켓의 파일 디스크립터.
 * ─────────────────────────────────────────────────────────────*/
static int g_demand_sock = -1;
static int g_initialized = 0;
static struct sockaddr_in g_demand_dst;

/**
 * @brief demand 런타임을 초기화합니다.
 *
 * demand 메시지를 보내기 위한 UDP 소켓을 생성하고
 * 목적지 주소를 설정합니다. 이미 초기화된 경우 즉시 반환합니다.
 */
int demand_runtime_init(void)
{
    if (g_initialized)
        return 0;

    /* non-blocking UDP 소켓 생성 */
    g_demand_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_demand_sock < 0) {
        perror("[demand] socket");
        return -1;
    }

    memset(&g_demand_dst, 0, sizeof(g_demand_dst));
    g_demand_dst.sin_family = AF_INET;
    g_demand_dst.sin_port   = htons(DEMAND6_DST_PORT);

    /*
     * 이 IP는 실험용 reserved endpoint.
     * 실제로는 Linux routing 상 wwan0 로 나가도록 잡아야 함.
     */
    if (inet_pton(AF_INET, "10.99.0.1", &g_demand_dst.sin_addr) != 1) {
        close(g_demand_sock);
        g_demand_sock = -1;
        return -1;
    }

    g_initialized = 1;
    return 0;
}

/**
 * @brief demand 런타임을 종료하고 자원을 해제합니다.
 */
void demand_runtime_fini(void)
{
    if (g_demand_sock >= 0) {
        close(g_demand_sock);
        g_demand_sock = -1;
    }
    g_initialized = 0;
}

/**
 * @brief 주어진 fd 가 demand 소켓 자신인지 확인합니다. (recursion guard)
 */
int is_demand_sockfd(int fd)
{
    return (fd == g_demand_sock);
}

/**
 * @brief 소켓 fd 로부터 플로우 메타데이터를 추출합니다.
 *
 * @param fd          대상 파일 디스크립터.
 * @param payload_len 페이로드 길이.
 * @param out         추출 결과를 저장할 구조체 포인터.
 * @return 성공 0, 실패(소켓 아닌 fd 포함) -1.
 */
int extract_flow_meta_from_fd(int fd, size_t payload_len, flow_meta_t *out)
{
    int sock_type = 0;
    socklen_t optlen = sizeof(sock_type);

    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));
    out->fd          = fd;
    out->payload_len = (uint32_t)payload_len;

    /* 소켓 타입(TCP/UDP) 확인 — 소켓이 아니면 여기서 -1 반환 */
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) < 0)
        return -1;

    out->sock_type = sock_type;

    if (sock_type == SOCK_DGRAM)
        out->l4_proto = IPPROTO_UDP;
    else if (sock_type == SOCK_STREAM)
        out->l4_proto = IPPROTO_TCP;
    else
        return -1;

    /* connect() 된 소켓이면 peer 주소 조회 */
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) == 0) {
        out->dst_ip_be   = peer.sin_addr.s_addr;
        out->dst_port_be = peer.sin_port;
    }

    /* 로컬 source port 조회 */
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0) {
        out->src_port_be = local.sin_port;
    }

    return 0;
}

/**
 * @brief 6G demand 패킷(demand6_t, 16 bytes)을 빌드합니다.
 *
 * @param fm            플로우 메타데이터.
 * @param app_type      app_type_t 값.
 * @param payload_bytes 예상 전송량 (bytes).
 * @param deadline_ms   soft deadline (ms, 0 = 없음).
 * @param buf           출력 버퍼.
 * @param buf_sz        버퍼 크기.
 * @param out_len       실제 기록된 바이트 수.
 * @return 성공 0, 실패 -1.
 */
int build_6g_information(const flow_meta_t *fm,
                         uint8_t           app_type,
                         uint32_t          payload_bytes,
                         uint16_t          deadline_ms,
                         uint8_t          *buf,
                         size_t            buf_sz,
                         size_t           *out_len)
{
    if (!fm || !buf || !out_len)
        return -1;

    if (buf_sz < sizeof(demand6_t))
        return -1;

    demand6_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.protocol_id   = htonl(DEMAND6_PROTOCOL_ID);
    pkt.app_type      = app_type;
    pkt._reserved     = 0;
    pkt.src_port      = fm->src_port_be;       /* already network order */
    pkt.payload_bytes = htonl(payload_bytes);
    pkt.deadline_ms   = htons(deadline_ms);
    pkt._pad          = 0;

    memcpy(buf, &pkt, sizeof(pkt));
    *out_len = sizeof(pkt);

    return 0;
}

/**
 * @brief 빌드된 demand 패킷을 side-channel(UDP)으로 전송합니다.
 *
 * @param buf 전송할 데이터.
 * @param len 데이터 길이.
 * @return 성공 0, 실패 -1.
 */
int send_demand_packet(const uint8_t *buf, size_t len)
{
    if (g_demand_sock < 0 || !buf || len == 0)
        return -1;

    ssize_t ret = sendto(g_demand_sock,
                         buf,
                         len,
                         MSG_DONTWAIT,
                         (struct sockaddr *)&g_demand_dst,
                         sizeof(g_demand_dst));

    return (ret < 0) ? -1 : 0;
}

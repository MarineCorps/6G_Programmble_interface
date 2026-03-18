/*
 * _GNU_SOURCE 매크로는 특정 기능(예: clock_gettime)을 사용하기 위해 필요합니다.
 * GNU 확장 기능을 활성화하여 표준 C 라이브러리에서 제공하지 않는 함수를 사용할 수 있게 합니다.
 */
#define _GNU_SOURCE

#include "intent_runtime.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// 전역 변수: 이 파일 내에서만 사용되는 정적(static) 변수들입니다.

// 인텐트 메시지를 보내는 데 사용될 UDP 소켓의 파일 디스크립터입니다.
static int g_intent_sock = -1;
// 런타임이 초기화되었는지 여부를 나타내는 플래그입니다. (0: 초기화 안됨, 1: 초기화됨)
static int g_initialized = 0;
// 현재 프로세스의 런타임 세션을 식별하는 ID입니다.
static uint32_t g_session_id = 0;
// 다음으로 할당할 인텐트의 고유 ID입니다.
static uint32_t g_next_intent_id = 1;
// g_next_intent_id에 대한 동시 접근을 막기 위한 뮤텍스(Mutex)입니다.
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
// 인텐트 메시지를 수신할 목적지의 주소 정보입니다.
static struct sockaddr_in g_intent_dst;

/**
 * @brief 현재 프로세스에 대한 고유한 세션 ID를 생성합니다.
 * 
 * @return uint32_t 생성된 세션 ID.
 * 
 * 이 함수는 보안 목적의 강력한 난수 대신, 프로세스 ID와 고정밀 타임스탬프를
 * XOR 연산하여 "프로세스 단위의 세션 식별"에 충분한 유일성을 제공하는 값을 만듭니다.
 */
uint32_t make_session_id(void)
{
    /*
     * 아주 강한 보안용 랜덤은 아니고,
     * "프로세스 단위 세션 식별" 정도로 충분한 값
     */
    struct timespec ts;
    // CLOCK_MONOTONIC은 시스템 시간을 변경해도 영향을 받지 않는 단조롭게 증가하는 시간입니다.
    clock_gettime(CLOCK_MONOTONIC, &ts);

    // 현재 프로세스의 ID를 32비트 정수로 변환합니다.
    uint32_t pid_part = (uint32_t)getpid();
    // 시간의 초(sec)와 나노초(nsec) 부분을 XOR하여 시간 기반의 고유 값을 생성합니다.
    uint32_t time_part = (uint32_t)(ts.tv_nsec ^ ts.tv_sec);

    // 프로세스 ID 부분과 시간 부분을 XOR하여 최종 세션 ID를 반환합니다.
    return pid_part ^ time_part;
}

/**
 * @brief 인텐트 런타임을 초기화합니다.
 * 
 * @return int 성공 시 0, 실패 시 -1.
 * 
 * 이 함수는 인텐트 메시지를 보내기 위한 UDP 소켓을 생성하고,
 * 목적지 주소를 설정하며, 세션 ID를 생성합니다.
 * 이미 초기화된 경우 아무 작업도 수행하지 않습니다.
 */
int intent_runtime_init(void)
{
    // 이미 초기화되었다면 즉시 0을 반환합니다.
    if (g_initialized)
        return 0;

    // 비차단(non-blocking) 모드의 UDP 소켓을 생성합니다.
    g_intent_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_intent_sock < 0) {
        perror("[intent] socket"); // 소켓 생성 실패 시 오류 메시지 출력
        return -1;
    }

    // 목적지 주소 구조체를 0으로 초기화합니다.
    memset(&g_intent_dst, 0, sizeof(g_intent_dst));
    g_intent_dst.sin_family = AF_INET; // 주소 체계는 IPv4
    g_intent_dst.sin_port = htons(48888); // 목적지 포트 번호 설정 (네트워크 바이트 순서로 변환)

    /*
     * 이 IP는 실험용 reserved endpoint
     * 실제로는 Linux routing 상 wwan0로 나가도록 잡아야 함
     */
    // 문자열 형태의 IP 주소를 네트워크 주소로 변환하여 설정합니다.
    if (inet_pton(AF_INET, "10.99.0.1", &g_intent_dst.sin_addr) != 1) {
        close(g_intent_sock); // 실패 시 소켓을 닫습니다.
        g_intent_sock = -1;
        return -1;
    }

    // 현재 세션의 ID를 생성합니다.
    g_session_id = make_session_id();
    // 초기화 플래그를 1로 설정합니다.
    g_initialized = 1;
    return 0;
}

/**
 * @brief 인텐트 런타임을 종료하고 자원을 해제합니다.
 */
void intent_runtime_fini(void)
{
    // 소켓이 열려있는 경우
    if (g_intent_sock >= 0) {
        close(g_intent_sock); // 소켓을 닫습니다.
        g_intent_sock = -1;   // 파일 디스크립터를 초기화합니다.
    }
    // 초기화 플래그를 0으로 리셋합니다.
    g_initialized = 0;
}

/**
 * @brief 주어진 파일 디스크립터가 인텐트 소켓인지 확인합니다.
 * 
 * @param fd 확인할 파일 디스크립터.
 * @return int 인텐트 소켓이면 1, 아니면 0.
 */
int is_intent_sockfd(int fd)
{
    return (fd == g_intent_sock);
}

/**
 * @brief 소켓 파일 디스크립터(fd)로부터 플로우 메타데이터를 추출합니다.
 * 
 * @param fd           메타데이터를 추출할 소켓의 파일 디스크립터.
 * @param payload_len  페이로드의 길이.
 * @param out          추출된 메타데이터를 저장할 구조체 포인터.
 * @return int         성공 시 0, 실패 시 -1.
 */
int extract_flow_meta_from_fd(int fd, size_t payload_len, flow_meta_t *out)
{
    int sock_type = 0;
    socklen_t optlen = sizeof(sock_type);

    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));
    out->fd = fd;
    out->payload_len = (uint32_t)payload_len;

    // 소켓 옵션을 조회하여 소켓의 타입(TCP/UDP)을 확인합니다.
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) < 0)
        return -1;

    out->sock_type = sock_type;

    // 소켓 타입에 따라 L4 프로토콜을 설정합니다.
    if (sock_type == SOCK_DGRAM)
        out->l4_proto = IPPROTO_UDP;
    else if (sock_type == SOCK_STREAM)
        out->l4_proto = IPPROTO_TCP;
    else
        return -1; // 지원하지 않는 소켓 타입

    /*
     * connect() 된 socket이면 peer 정보 조회 가능
     */
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    // 소켓이 연결된 경우, 상대방(peer)의 주소 정보를 가져옵니다.
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) == 0) {
        out->dst_ip_be   = peer.sin_addr.s_addr; // 목적지 IP (네트워크 바이트 순서)
        out->dst_port_be = peer.sin_port;       // 목적지 포트 (네트워크 바이트 순서)
    }

    /*
     * local source port 조회
     */
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    // 로컬 소켓의 주소 정보를 가져와 출발지 포트를 확인합니다.
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0) {
        out->src_port_be = local.sin_port; // 출발지 포트 (네트워크 바이트 순서)
    }

    return 0;
}

/**
 * @brief 인텐트 패킷을 생성합니다.
 * 
 * @param fm             플로우 메타데이터.
 * @param phase          인텐트의 단계.
 * @param confidence     인텐트의 신뢰도.
 * @param eta_ms         예상 도착 시간 (밀리초).
 * @param expected_bytes 예상 데이터 크기 (바이트).
 * @param deadline_us    마감 기한 (마이크로초).
 * @param buf            생성된 패킷을 저장할 버퍼.
 * @param buf_sz         버퍼의 크기.
 * @param out_len        생성된 패킷의 길이를 저장할 포인터.
 * @return int           성공 시 0, 실패 시 -1.
 */
int build_intent_packet(const flow_meta_t *fm,
                        uint8_t phase,
                        uint8_t confidence,
                        uint16_t eta_ms,
                        uint32_t expected_bytes,
                        uint32_t deadline_us,
                        uint8_t *buf,
                        size_t buf_sz,
                        size_t *out_len)
{
    if (!fm || !buf || !out_len)
        return -1;

    // 버퍼 크기가 인텐트 패킷 구조체보다 작은지 확인합니다.
    if (buf_sz < sizeof(intent_pkt_t))
        return -1;

    intent_pkt_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    // --- 패킷 헤더 채우기 ---
    pkt.hdr.magic     = htonl(INTENT_MAGIC);     // 매직 넘버 (네트워크 바이트 순서)
    pkt.hdr.version   = INTENT_VERSION;          // 프로토콜 버전
    pkt.hdr.msg_type  = INTENT_MSG_DECLARE;      // 메시지 타입 (인텐트 선언)
    pkt.hdr.total_len = htons((uint16_t)sizeof(pkt)); // 전체 패킷 길이 (네트워크 바이트 순서)

    // --- 바인딩 정보 채우기 ---
    pkt.bind.l4_proto          = fm->l4_proto;
    pkt.bind.original_dst_ip   = fm->dst_ip_be;
    pkt.bind.original_dst_port = fm->dst_port_be;
    pkt.bind.original_src_port = fm->src_port_be;
    pkt.bind.session_id        = htonl(g_session_id); // 현재 세션 ID (네트워크 바이트 순서)

    // --- 인텐트 ID 할당 (Thread-safe) ---
    pthread_mutex_lock(&g_lock); // 뮤텍스 잠금
    pkt.bind.intent_id         = htonl(g_next_intent_id++); // 다음 ID 할당 후 1 증가 (네트워크 바이트 순서)
    pthread_mutex_unlock(&g_lock); // 뮤텍스 해제

    // --- 힌트 정보 채우기 ---
    pkt.hint.phase            = phase;
    pkt.hint.confidence       = confidence;
    pkt.hint.eta_ms           = htons(eta_ms);           // 예상 도착 시간 (네트워크 바이트 순서)
    pkt.hint.expected_bytes   = htonl(expected_bytes);   // 예상 데이터 크기 (네트워크 바이트 순서)
    pkt.hint.deadline_us      = htonl(deadline_us);      // 마감 기한 (네트워크 바이트 순서)

    // 완성된 패킷 구조체를 출력 버퍼로 복사합니다.
    memcpy(buf, &pkt, sizeof(pkt));
    *out_len = sizeof(pkt); // 실제 길이를 out_len에 저장합니다.

    return 0;
}

/**
 * @brief 생성된 인텐트 패킷을 전송합니다.
 * 
 * @param buf 보낼 데이터가 담긴 버퍼.
 * @param len 보낼 데이터의 길이.
 * @return int 성공 시 0, 실패 시 -1.
 */
int send_intent_packet(const uint8_t *buf, size_t len)
{
    // 런타임이 초기화되지 않았거나 버퍼가 유효하지 않으면 실패 처리합니다.
    if (g_intent_sock < 0 || !buf || len == 0)
        return -1;

    // sendto를 사용하여 지정된 목적지로 데이터를 전송합니다.
    // MSG_DONTWAIT 플래그를 사용하여 비차단(non-blocking)으로 동작합니다.
    ssize_t ret = sendto(g_intent_sock,
                         buf,
                         len,
                         MSG_DONTWAIT,
                         (struct sockaddr *)&g_intent_dst,
                         sizeof(g_intent_dst));

    // sendto 호출이 실패하면 -1을 반환합니다.
    if (ret < 0)
        return -1;

    return 0;
}
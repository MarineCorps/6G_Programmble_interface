#define _GNU_SOURCE

#include "intent_runtime.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── 실제 libc 함수 포인터 ─────────────────────────────────────── */
typedef ssize_t (*send_fn_t)  (int, const void *, size_t, int);
typedef ssize_t (*sendto_fn_t)(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t);
typedef ssize_t (*write_fn_t) (int, const void *, size_t);

static send_fn_t   real_send   = NULL;
static sendto_fn_t real_sendto = NULL;
static write_fn_t  real_write  = NULL;

static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void hook_init_once(void)
{
    intent_runtime_init();
    real_send   = (send_fn_t)  dlsym(RTLD_NEXT, "send");
    real_sendto = (sendto_fn_t)dlsym(RTLD_NEXT, "sendto");
    real_write  = (write_fn_t) dlsym(RTLD_NEXT, "write");
}

/* ── 공통 helper ──────────────────────────────────────────────────
 * 모든 hook이 이 함수 하나를 호출한다.
 *
 * dest_addr: sendto()처럼 호출자가 이미 목적지 주소를 알고 있으면 전달.
 *            send()/write()처럼 connected socket이거나 모르면 NULL.
 *
 * 내부 동작:
 *   1. recursion guard (intent 소켓 자신이면 즉시 return)
 *   2. extract_flow_meta_from_fd() 로 fd 에서 TCP/UDP·주소 추출
 *      → 소켓이 아닌 fd(파일, 파이프)는 여기서 -1 반환되어 skip
 *   3. dest_addr 가 주어지면 fm 의 dst 필드를 그 값으로 덮어씀
 *      (unconnected UDP sendto 케이스)
 *   4. intent 패킷 생성 → 전송
 * ────────────────────────────────────────────────────────────── */
static void try_send_intent(int fd,
                            const struct sockaddr *dest_addr,
                            socklen_t addrlen,
                            size_t len)
{
    /* 1. recursion guard */
    if (is_intent_sockfd(fd))
        return;

    /* 2. fd 가 소켓인지 확인 + TCP/UDP 구분 + 주소 추출 */
    flow_meta_t fm;
    if (extract_flow_meta_from_fd(fd, len, &fm) != 0)
        return;

    /* 3. sendto() 경로: dest_addr 에서 dst 정보 덮어쓰기 */
    if (dest_addr &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in) &&
        dest_addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)dest_addr;
        fm.dst_ip_be   = sin->sin_addr.s_addr;
        fm.dst_port_be = sin->sin_port;
    }

    /* 4. intent 패킷 생성 + 전송 */
    uint8_t ibuf[256];
    size_t  ilen = 0;
    if (build_intent_packet(&fm,
                            INTENT_PHASE_PRE_TX,
                            80,
                            2,
                            (uint32_t)len,
                            10000,
                            ibuf,
                            sizeof(ibuf),
                            &ilen) == 0) {
        (void)send_intent_packet(ibuf, ilen);
    }
}

/* ── send() hook ──────────────────────────────────────────────── */
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    pthread_once(&g_once, hook_init_once);
    if (!real_send)
        return -1;

    try_send_intent(sockfd, NULL, 0, len);
    return real_send(sockfd, buf, len, flags);
}

/* ── sendto() hook ────────────────────────────────────────────── */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    pthread_once(&g_once, hook_init_once);
    if (!real_sendto)
        return -1;

    try_send_intent(sockfd, dest_addr, addrlen, len);
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/* ── write() hook ─────────────────────────────────────────────────
 * iperf3 등은 send()/sendto() 대신 write()로 소켓에 데이터를 씀.
 * 소켓이 아닌 일반 파일/파이프 fd 는 try_send_intent 내부에서
 * extract_flow_meta_from_fd() 가 -1 을 반환해 자동으로 skip 된다.
 * ────────────────────────────────────────────────────────────── */
ssize_t write(int fd, const void *buf, size_t len)
{
    pthread_once(&g_once, hook_init_once);
    if (!real_write)
        return -1;

    try_send_intent(fd, NULL, 0, len);
    return real_write(fd, buf, len);
}

/* ── 프로세스 종료 시 자동 정리 ───────────────────────────────── */
__attribute__((destructor))
static void hook_fini(void)
{
    intent_runtime_fini();
}

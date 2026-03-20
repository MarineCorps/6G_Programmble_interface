#define _GNU_SOURCE

#include "6g_new_api.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ── 환경변수로 주입되는 앱 설정 ───────────────────────────────── */
static uint8_t  g_app_type    = APP_UNKNOWN;
static uint16_t g_deadline_ms = 0;

static pthread_once_t g_once = PTHREAD_ONCE_INIT;

/* ── 초기화 ─────────────────────────────────────────────────────
 *   LD_PRELOAD 진입 시 딱 한 번 실행.
 *   환경변수 예:
 *     DEMAND_APP_TYPE=1   (APP_LLM)
 *     DEMAND_DEADLINE_MS=10
 * ──────────────────────────────────────────────────────────── */
static void hook_init_once(void)
{
    /* 환경변수에서 앱 종류와 deadline 읽기 */
    const char *app_env = getenv("DEMAND_APP_TYPE");
    const char *dl_env  = getenv("DEMAND_DEADLINE_MS");
    if (app_env) g_app_type    = (uint8_t)atoi(app_env);
    if (dl_env)  g_deadline_ms = (uint16_t)atoi(dl_env);

    demand_runtime_init();

    real_send   = (send_fn_t)  dlsym(RTLD_NEXT, "send");
    real_sendto = (sendto_fn_t)dlsym(RTLD_NEXT, "sendto");
    real_write  = (write_fn_t) dlsym(RTLD_NEXT, "write");
}

/* ── send_6g: 모든 hook의 공통 처리 ────────────────────────────
 *
 *   참고: 함수명을 '6g_send'로 하면 C 식별자 규칙상
 *   (숫자 시작 불가) 컴파일 에러가 나므로 send_6g 로 정의.
 *
 *   동작 순서:
 *     1. recursion guard — demand 소켓 자신이면 즉시 return
 *     2. extract_flow_meta_from_fd() — 비소켓 fd(파일/파이프) skip
 *     3. sendto() 경로면 dest_addr로 fm.dst 덮어쓰기
 *     4. build_6g_information() → send_demand_packet()
 * ──────────────────────────────────────────────────────────── */
static void send_6g(int fd,
                    const struct sockaddr *dest_addr,
                    socklen_t addrlen,
                    size_t len)
{
    /* 1. recursion guard */
    if (is_demand_sockfd(fd))
        return;

    /* 2. 소켓 여부 확인 + flow 메타 추출 */
    flow_meta_t fm;
    if (extract_flow_meta_from_fd(fd, len, &fm) != 0)
        return;

    /* 3. unconnected UDP sendto() 경로: 목적지 정보 덮어쓰기 */
    if (dest_addr &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in) &&
        dest_addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)dest_addr;
        fm.dst_ip_be   = sin->sin_addr.s_addr;
        fm.dst_port_be = sin->sin_port;
    }

    /* 4. 6G demand 패킷 빌드 후 side-channel 전송 */
    uint8_t ibuf[32];
    size_t  ilen = 0;
    if (build_6g_information(&fm,
                             g_app_type,
                             (uint32_t)len,
                             g_deadline_ms,
                             ibuf,
                             sizeof(ibuf),
                             &ilen) == 0) {
        (void)send_demand_packet(ibuf, ilen);
    }
}

/* ── send() hook ────────────────────────────────────────────── */
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    pthread_once(&g_once, hook_init_once);
    if (!real_send)
        return -1;

    send_6g(sockfd, NULL, 0, len);
    return real_send(sockfd, buf, len, flags);
}

/* ── sendto() hook ──────────────────────────────────────────── */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    pthread_once(&g_once, hook_init_once);
    if (!real_sendto)
        return -1;

    send_6g(sockfd, dest_addr, addrlen, len);
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/* ── write() hook ───────────────────────────────────────────── */
ssize_t write(int fd, const void *buf, size_t len)
{
    pthread_once(&g_once, hook_init_once);
    if (!real_write)
        return -1;

    send_6g(fd, NULL, 0, len);
    return real_write(fd, buf, len);
}

/* ── 프로세스 종료 시 자동 정리 ─────────────────────────────── */
__attribute__((destructor))
static void hook_fini(void)
{
    demand_runtime_fini();
}
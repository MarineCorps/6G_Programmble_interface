# 6G demand side-channel — UE 측 LD_PRELOAD shim
#
# 빌드:
#   make
#
# 사용:
#   DEMAND_DST_IP=192.168.70.135 \
#   DEMAND_APP_TYPE=1 DEMAND_DEADLINE_MS=10 \
#   LD_PRELOAD=./libdemand_hook.so iperf3 -c <server> ...
#
#   DEMAND_DST_IP       demand 패킷 목적지. 5G PDU 세션을 타야 한다. (필수)
#   DEMAND_APP_TYPE     0=UNKNOWN 1=LLM(8x) 2=VLA(4x) 3=VIDEO(2x) 4=BULK(1x)
#   DEMAND_DEADLINE_MS  soft deadline. 0 = 없음.
#
# 단발 발사만 필요하면 shim 없이 send_demand.py 를 쓰는 게 간단하다.
#
# 참고: 예전에는 libdemand_hook.c 와 6g_new_api.c 가 send/sendto/write 를
# 둘 다 정의해서 (같은 심볼) 동시 빌드가 불가능했고, SRCS 에 들어 있던
# libdemand_hook.c 쪽은 app_type 을 APP_UNKNOWN 으로 하드코딩해 가중치가
# 영원히 1.0 이었다. 환경변수를 읽는 6g_new_api.c 만 남겼다.
# .so 파일명은 기존 LD_PRELOAD 명령을 깨지 않도록 그대로 유지한다.

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -fPIC
LDFLAGS = -shared -ldl -lpthread

SRCS = 6g_new_api.c demand_runtime.c
OBJS = $(SRCS:.c=.o)

TARGET = libdemand_hook.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c demand_runtime.h demand_pkt.h 6g_new_api.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

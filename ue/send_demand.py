#!/usr/bin/env python3
# send_demand.py — 6G demand(control) 패킷 1발 전송기 (LD_PRELOAD shim 대체용)
#
# intent_parser.c 가 인식하는 wire format 그대로:
#   [protocol_id 4B '6GNI'][app_type 1B][_reserved 1B]
#   [src_port 2B][payload_bytes 4B][deadline_ms 2B][_pad 2B]  = 16B
#
# app_type: 1=LLM(8x) 2=VLA(4x) 3=VIDEO(2x) 0/4=OFF(1x)
#
# 사용:
#   python3 send_demand.py <dst_ip> <app_type> [deadline_ms] [payload_bytes]
# 예 (ON, LLM 8x):   python3 send_demand.py 192.168.70.135 1 10 1000000
# 예 (OFF, 1x):      python3 send_demand.py 192.168.70.135 4
#
# 주의: dst_ip 로 가는 경로가 5G PDU 세션(=iperf 가 나가는 그 인터페이스)을
#       타야 gNB PDCP UL hook 이 이 패킷을 본다. 아무도 48888 을 listen 할
#       필요 없음 — gNB 는 UPF 로 포워딩하기 *전에* 이미 후킹한다.

import socket, struct, sys, os, time

DEMAND6_PROTOCOL_ID = 0x36474E49  # '6GNI'
DEMAND6_UDP_PORT    = 48888

def build(app_type, src_port=12345, payload_bytes=1_000_000, deadline_ms=0):
    # '!' = network byte order; codelet 이 ntohl/ntohs 로 되돌려 읽음
    return struct.pack('!IBBHIHH',
                       DEMAND6_PROTOCOL_ID,  # protocol_id
                       app_type & 0xFF,      # app_type
                       0,                    # _reserved
                       src_port & 0xFFFF,    # src_port
                       payload_bytes & 0xFFFFFFFF,  # payload_bytes
                       deadline_ms & 0xFFFF, # deadline_ms
                       0)                    # _pad

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    dst_ip   = sys.argv[1]
    app_type = int(sys.argv[2])
    deadline = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    payload  = int(sys.argv[4]) if len(sys.argv) > 4 else 1_000_000

    pkt = build(app_type, deadline_ms=deadline, payload_bytes=payload)
    assert len(pkt) == 16, f"packet must be 16B, got {len(pkt)}"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    label = {1: "LLM 8x", 2: "VLA 4x", 3: "VIDEO 2x"}.get(app_type, "OFF 1x")

    # DEMAND_LOOP_MS 환경변수가 있으면 heartbeat 모드 (동적 감쇠 데모용).
    # codelet 의 duration_ms(TTL) 보다 *짧은* 간격으로 보내야 깜박이지 않음.
    # 예) TTL=500ms 면 LOOP_MS=250 (2x 마진). Ctrl-C 로 중단 → TTL 후 자동 OFF.
    loop_ms = int(os.environ.get("DEMAND_LOOP_MS", "0"))
    if loop_ms > 0:
        print(f"heartbeat → {dst_ip}:{DEMAND6_UDP_PORT}  app_type={app_type} ({label})  every {loop_ms}ms  (Ctrl-C to stop)")
        try:
            while True:
                s.sendto(pkt, (dst_ip, DEMAND6_UDP_PORT))
                time.sleep(loop_ms / 1000.0)
        except KeyboardInterrupt:
            print("\nstopped — weight will expire after the codelet TTL")
    else:
        s.sendto(pkt, (dst_ip, DEMAND6_UDP_PORT))
        print(f"sent demand6 → {dst_ip}:{DEMAND6_UDP_PORT}  app_type={app_type} ({label})  16B")

if __name__ == "__main__":
    main()

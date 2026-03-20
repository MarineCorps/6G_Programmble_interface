CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -fPIC
LDFLAGS = -shared -ldl -lpthread

SRCS = libdemand_hook.c demand_runtime.c
OBJS = $(SRCS:.c=.o)

TARGET = libdemand_hook.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c demand_runtime.h demand_pkt.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

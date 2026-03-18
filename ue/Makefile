CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -fPIC
LDFLAGS = -shared -ldl -lpthread

SRCS = libintent_hook.c intent_runtime.c
OBJS = $(SRCS:.c=.o)

TARGET = libintent_hook.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c intent_runtime.h intent_pkt.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)
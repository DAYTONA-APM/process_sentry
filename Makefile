CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -Iinclude -D_POSIX_C_SOURCE=200809L
TARGET = proc-sentry

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

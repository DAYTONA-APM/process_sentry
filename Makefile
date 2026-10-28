CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -ansi -Iinclude -D_POSIX_C_SOURCE=200809L

SRCS = src/crawler.c src/exe_audit.c
OBJS = $(SRCS:.c=.o)

TARGET = proc-sentry
TEST_CRAWLER = test_crawler
TEST_EXE = test_exe

all: $(TARGET)

$(TARGET): $(OBJS) src/main.o
	$(CC) $(CFLAGS) -o $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

test_crawler: tests/test_crawler.c src/crawler.o
	$(CC) $(CFLAGS) -o $@ $^

test_exe: tests/test_exe.c src/exe_audit.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f src/*.o tests/*.o $(TARGET) $(TEST_CRAWLER) $(TEST_EXE) /tmp/proc_sentry_dummy

.PHONY: all clean test_crawler test_exe

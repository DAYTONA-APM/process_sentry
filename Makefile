CC = cc
CFLAGS = -Wall -Wextra -pedantic -ansi -Iinclude -D_POSIX_C_SOURCE=200809L

OBJS = src/crawler.o src/exe_audit.o src/maps_audit.o src/env_audit.o

all: proc-sentry

proc-sentry: src/main.c $(OBJS)
	$(CC) $(CFLAGS) src/main.c $(OBJS) -o proc-sentry

src/crawler.o: src/crawler.c include/crawler.h
	$(CC) $(CFLAGS) -c src/crawler.c -o src/crawler.o

src/exe_audit.o: src/exe_audit.c include/exe_audit.h
	$(CC) $(CFLAGS) -c src/exe_audit.c -o src/exe_audit.o

src/maps_audit.o: src/maps_audit.c include/maps_audit.h
	$(CC) $(CFLAGS) -c src/maps_audit.c -o src/maps_audit.o

src/env_audit.o: src/env_audit.c include/env_audit.h
	$(CC) $(CFLAGS) -c src/env_audit.c -o src/env_audit.o

test_env: tests/test_env.c src/env_audit.o
	$(CC) $(CFLAGS) tests/test_env.c src/env_audit.o -o test_env

test_crawler: tests/test_crawler.c src/crawler.o
	$(CC) $(CFLAGS) tests/test_crawler.c src/crawler.o -o test_crawler

test_exe: tests/test_exe.c src/exe_audit.o
	$(CC) $(CFLAGS) tests/test_exe.c src/exe_audit.o -o test_exe

test_maps: tests/test_maps.c src/maps_audit.o
	$(CC) $(CFLAGS) tests/test_maps.c src/maps_audit.o -o test_maps

clean:
	rm -f src/*.o tests/*.o proc-sentry test_crawler test_exe test_maps test_env /tmp/proc_sentry_dummy

.PHONY: all clean

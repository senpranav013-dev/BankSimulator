CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread

server: server.c bank.c auth.c bank.h auth.h
	$(CC) $(CFLAGS) -o server server.c bank.c auth.c -lm

run: server
	./server

clean:
	rm -f server

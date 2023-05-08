CC=gcc
CFLAGS=-I.
# DEPS = hellomake.h
OBJ = socket_client.o
# OBJ = socket_server.o

# %.o: %.c $(DEPS)
# 	$(CC) -c -o $@ $< $(CFLAGS)

# socket_server: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

socket_client: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
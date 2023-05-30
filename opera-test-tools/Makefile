CC=gcc
CFLAGS=-I.
# DEPS = hellomake.h
# OBJ = socket_client.o
# OBJ = rtt_server.o
OBJ = rtt_client.o

# %.o: %.c $(DEPS)
# 	$(CC) -c -o $@ $< $(CFLAGS)

# socket_server: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

# socket_client: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

# rtt_server: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

rtt_client: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
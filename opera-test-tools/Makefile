CC=gcc
CFLAGS=-I.
# DEPS = hellomake.h
# OBJ = socket_client.o
# OBJ = udp_s.o
OBJ = udp_c.o

# %.o: %.c $(DEPS)
# 	$(CC) -c -o $@ $< $(CFLAGS)

# socket_server: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

# socket_client: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

# udp_server: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS)

udp_client: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
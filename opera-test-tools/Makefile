CC=gcc
CFLAGS=-I.

objects = udp_s udp_c
all: $(objects)

$(objects): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(objects)

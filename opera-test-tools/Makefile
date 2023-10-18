CC=gcc
CFLAGS=-I.

objects = udp_s_timing udp_c_timing
all: $(objects)

$(objects): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(objects)

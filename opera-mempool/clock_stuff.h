#define DEVICE "/dev/ptp3"

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

static clockid_t get_nic_clock_id(void)
{
	int fd;
    char *device = DEVICE;
    clockid_t clkid;

    fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "opening %s: %s\n", device, strerror(errno));
		return -1;
	}

	clkid = FD_TO_CLOCKID(fd);
	if (CLOCK_INVALID == clkid) {
		fprintf(stderr, "failed to read clock id\n");
		return -1;
	}
	return clkid;
}

static unsigned long get_nsec(struct timespec *ts)
{
    return ts->tv_sec * 1000000000UL + ts->tv_nsec;
}

static struct timespec get_nicclock(void)
{
	struct timespec ts;
	clock_gettime(clkid, &ts);
	return ts;
}

static void read_time()
{
	// struct timespec now = get_realtime();
	now = get_nicclock();
	unsigned long current_time_ns = get_nsec(&now);
	// t1ms = now_ns / 1000000; // number of 1's of milliseconds 
	time_into_cycle_ns = current_time_ns % cycle_time_ns;
	topo = (time_into_cycle_ns / slot_time_ns) + 1;
}

static void signal_handler(int sig)
{
	// printf("signal_handler");
	quit = 1;
}
/**
 * Ring buffer is a fixed-size queue, implemented as a table of
 * pointers. Head and tail pointers are modified atomically, allowing
 * concurrent access to it. It has the following features:
 * - FIFO (First In First Out)
 * - Maximum size is fixed; the pointers are stored in a table.
 * - Lockless implementation.
 *
 * The ring buffer implementation is not preemptable.
 */
#define _GNU_SOURCE 
#include <stdbool.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <net/if.h>

#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <linux/ptp_clock.h>

/* typically 64 bytes on x86/x64 CPUs */
#define CACHE_LINE_SIZE 64

#ifndef __compiler_barrier
#define __compiler_barrier()             \
    do {                                 \
        asm volatile("" : : : "memory"); \
    } while (0)
#endif

/* The producer and the consumer have a head and a tail index. The particularity
 * of these index is that they are not between 0 and size(ring). These indexes
 * are between 0 and 2^32, and we mask their value when we access the ring[]
 * field. Thanks to this assumption, we can do subtractions between 2 index
 * values in a modulo-32bit base: that is why the overflow of the indexes is not
 * a problem.
 */
typedef struct {
    struct {                          /** Ring producer status. */
        uint32_t watermark;           /**< Maximum items before EDQUOT. */
        uint32_t size;                /**< Size of ring buffer. */
        uint32_t mask;                /**< Mask (size - 1) of ring buffer. */
        volatile uint32_t head, tail; /**< Producer head and tail. */
    } prod __attribute__((__aligned__(CACHE_LINE_SIZE)));

    struct {                          /** Ring consumer status. */
        uint32_t size;                /**< Size of the ring buffer. */
        uint32_t mask;                /**< Mask (size - 1) of ring buffer. */
        volatile uint32_t head, tail; /**< Consumer head and tail. */
    } cons __attribute__((__aligned__(CACHE_LINE_SIZE)));

    void *ring[] __attribute__((__aligned__(CACHE_LINE_SIZE)));
} ringbuf_t;

/* true if x is a power of 2 */
#define IS_POWEROF2(x) ((((x) -1) & (x)) == 0)
#define RING_SIZE_MASK (unsigned) (0x0fffffff) /**< Ring size mask */
#define ALIGN_CEIL(val, align) \
    (typeof(val))((val) + (-(typeof(val))(val) & ((align) -1)))

/* Calculate the memory size needed for a ring buffer.
 *
 * This function returns the number of bytes needed for a ring buffer, given
 * the number of elements in it. This value is the sum of the size of the
 * structure ringbuf and the size of the memory needed by the objects pointers.
 * The value is aligned to a cache line size.
 *
 * @param count
 *   The number of elements in the ring buffer (must be a power of 2).
 * @return
 *   - The memory size occupied by the ring buffer on success.
 *   - -EINVAL if count is not a power of 2.
 */
ssize_t ringbuf_get_memsize(const unsigned count)
{
    /* Requested size is invalid, must be power of 2, and do not exceed the
     * size limit RING_SIZE_MASK.
     */
    if ((!IS_POWEROF2(count)) || (count > RING_SIZE_MASK))
        return -EINVAL;

    ssize_t sz = sizeof(ringbuf_t) + count * sizeof(void *);
    sz = ALIGN_CEIL(sz, CACHE_LINE_SIZE);
    return sz;
}

/* Initialize a ring buffer.
 *
 * The ring size is set to *count*, which must be a power of two. Water
 * marking is disabled by default. The real usable ring size is (count - 1)
 * instead of (count) to differentiate a free ring from an empty ring buffer.
 *
 * @param r
 *   The pointer to the ring buffer structure followed by the objects table.
 * @param count
 *   The number of elements in the ring buffer (must be a power of 2).
 * @return
 *   0 on success, or a negative value on error.
 */
int ringbuf_init(ringbuf_t *r, const unsigned count)
{
    memset(r, 0, sizeof(*r));
    r->prod.watermark = count, r->prod.size = r->cons.size = count;
    r->prod.mask = r->cons.mask = count - 1;
    r->prod.head = r->cons.head = 0, r->prod.tail = r->cons.tail = 0;

    return 0;
}

/* Create a ring buffer.
 *
 * The real usable ring size is (count - 1) instead of (count) to
 * differentiate a free ring from an empty ring buffer.
 *
 * @param count
 *   The size of the ring (must be a power of 2).
 * @return
 *   On success, the pointer to the new allocated ring buffer. NULL on error
 *   with errno set appropriately. Possible errno values include:
 *    - EINVAL - count provided is not a power of 2
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
ringbuf_t *ringbuf_create(const unsigned count)
{
    ssize_t ring_size = ringbuf_get_memsize(count);
    if (ring_size < 0)
        return NULL;

    ringbuf_t *r = malloc(ring_size);
    if (r)
        ringbuf_init(r, count);
    return r;
}

/* Release all memory used by the ring buffer.
 *
 * @param r
 *   Ring to free
 */
void ringbuf_free(ringbuf_t *r)
{
    free(r);
}

/* The actual enqueue of pointers on the ring buffer.
 * Placed here since identical code needed in both single- and multi- producer
 * enqueue functions.
 */
#define ENQUEUE_PTRS()                                                     \
    do {                                                                   \
        const uint32_t size = r->prod.size;                                \
        uint32_t i, idx = prod_head & mask;                                \
        if (idx + n < size) {                                              \
            for (i = 0; i < (n & ((~(unsigned) 0x3))); i += 4, idx += 4) { \
                r->ring[idx] = obj_table[i];                               \
                r->ring[idx + 1] = obj_table[i + 1];                       \
                r->ring[idx + 2] = obj_table[i + 2];                       \
                r->ring[idx + 3] = obj_table[i + 3];                       \
            }                                                              \
            switch (n & 0x3) {                                             \
            case 3:                                                        \
                r->ring[idx++] = obj_table[i++];                           \
            case 2:                                                        \
                r->ring[idx++] = obj_table[i++];                           \
            case 1:                                                        \
                r->ring[idx++] = obj_table[i++];                           \
            }                                                              \
        } else {                                                           \
            for (i = 0; idx < size; i++, idx++)                            \
                r->ring[idx] = obj_table[i];                               \
            for (idx = 0; i < n; i++, idx++)                               \
                r->ring[idx] = obj_table[i];                               \
        }                                                                  \
    } while (0)

/* The actual copy of pointers on the ring to obj_table.
 * Placed here since identical code needed in both single- and multi- consumer
 * dequeue functions.
 */
#define DEQUEUE_PTRS()                                                   \
    do {                                                                 \
        uint32_t idx = cons_head & mask;                                 \
        uint32_t i, size = r->cons.size;                                 \
        if (idx + n < size) {                                            \
            for (i = 0; i < (n & (~(unsigned) 0x3)); i += 4, idx += 4) { \
                obj_table[i] = r->ring[idx];                             \
                obj_table[i + 1] = r->ring[idx + 1];                     \
                obj_table[i + 2] = r->ring[idx + 2];                     \
                obj_table[i + 3] = r->ring[idx + 3];                     \
            }                                                            \
            switch (n & 0x3) {                                           \
            case 3:                                                      \
                obj_table[i++] = r->ring[idx++];                         \
            case 2:                                                      \
                obj_table[i++] = r->ring[idx++];                         \
            case 1:                                                      \
                obj_table[i++] = r->ring[idx++];                         \
            }                                                            \
        } else {                                                         \
            for (i = 0; idx < size; i++, idx++)                          \
                obj_table[i] = r->ring[idx];                             \
            for (idx = 0; i < n; i++, idx++)                             \
                obj_table[i] = r->ring[idx];                             \
        }                                                                \
    } while (0)

/* Enqueue several objects on a ring buffer (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring buffer structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring buffer from the obj_table.
 * @return
 *   - 0: Success; objects enqueue.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue, no object is enqueued.
 */
static inline int ringbuffer_sp_do_enqueue(ringbuf_t *r,
                                           void *const *obj_table,
                                           const unsigned n)
{
    uint32_t mask = r->prod.mask;
    uint32_t prod_head = r->prod.head, cons_tail = r->cons.tail;
    /* The subtraction is done between two unsigned 32-bits value (the result
     * is always modulo 32 bits even if we have prod_head > cons_tail). So
     * @free_entries is always between 0 and size(ring) - 1.
     */
    uint32_t free_entries = mask + cons_tail - prod_head;

    /* check that we have enough room in ring buffer */
    if ((n > free_entries))
        return -ENOBUFS;

    uint32_t prod_next = prod_head + n;
    r->prod.head = prod_next;

    /* write entries in ring buffer */
    ENQUEUE_PTRS();
    __compiler_barrier();

    r->prod.tail = prod_next;

    /* if we exceed the watermark */
    return ((mask + 1) - free_entries + n) > r->prod.watermark ? -EDQUOT : 0;
}

/* Dequeue several objects from a ring buffer (NOT multi-consumers safe).
 * When the request objects are more than the available objects, only dequeue
 * the actual number of objects
 *
 * @param r
 *   A pointer to the ring buffer structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to dequeue from the ring buffer to the obj_table.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring buffer to dequeue; no object is
 *     dequeued.
 */
static inline int ringbuffer_sc_do_dequeue(ringbuf_t *r,
                                           void **obj_table,
                                           const unsigned n)
{
    uint32_t mask = r->prod.mask;
    uint32_t cons_head = r->cons.head, prod_tail = r->prod.tail;
    /* The subtraction is done between two unsigned 32-bits value (the result
     * is always modulo 32 bits even if we have cons_head > prod_tail). So
     * @entries is always between 0 and size(ring) - 1.
     */
    uint32_t entries = prod_tail - cons_head;

    if (n > entries)
        return -ENOENT;

    uint32_t cons_next = cons_head + n;
    r->cons.head = cons_next;

    /* copy in table */
    DEQUEUE_PTRS();
    __compiler_barrier();

    r->cons.tail = cons_next;
    return 0;
}

/* Enqueue one object on a ring buffer (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring buffer structure.
 * @param obj
 *   A pointer to the object to be added.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring buffer to enqueue; no object
 *     is enqueued.
 */
static inline int ringbuf_sp_enqueue(ringbuf_t *r, void *obj)
{
    return ringbuffer_sp_do_enqueue(r, &obj, 1);
}

/**
 * Dequeue one object from a ring buffer (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring buffer to dequeue, no object
 *     is dequeued.
 */
static inline int ringbuf_sc_dequeue(ringbuf_t *r, void **obj_p)
{
    return ringbuffer_sc_do_dequeue(r, obj_p, 1);
}

/* Test if a ring buffer is full.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   - true: The ring is full.
 *   - false: The ring is not full.
 */
static inline bool ringbuf_is_full(const ringbuf_t *r)
{
    uint32_t prod_tail = r->prod.tail, cons_tail = r->cons.tail;
    return ((cons_tail - prod_tail - 1) & r->prod.mask) == 0;
}

/* Test if a ring buffer is empty.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   - true: The ring is empty.
 *   - false: The ring is not empty.
 */
static inline bool ringbuf_is_empty(const ringbuf_t *r)
{
    uint32_t prod_tail = r->prod.tail, cons_tail = r->cons.tail;
    return cons_tail == prod_tail;
}

typedef __u64 u64;
typedef __u32 u32;

struct burst_rx {
	__u64 addr;
	__u32 len;
}__attribute__((packed));

struct burst_tx {
	__u64 addr;
	__u32 len;
}__attribute__((packed));

struct thread_data {
	u32 cpu_core_id;
	ringbuf_t *rb;
	int quit;
};

#ifndef MAX_THREADS
#define MAX_THREADS 2
#endif

static struct thread_data thread_data[MAX_THREADS];
static pthread_t threads[MAX_THREADS];
static int n_threads;

#include <assert.h>

static void *
thread_func_pop(void *arg)
{
	
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	ringbuf_t *q = t->rb;
	
    while (!t->quit) {
        // u32 i;
        void *obj = malloc(sizeof(struct burst_tx));
         for (int i = 0; !ringbuf_is_empty(q); i++) {
            // void *obj;
            
			// struct burst_tx btx_test;
			ringbuf_sc_dequeue(q, &obj);
			struct burst_tx *btx = (struct burst_tx*)obj;
			printf("POP addr %lld \n", btx->addr);
        }
    }
    return NULL;
}

static void *
thread_func_push(void *arg)
{
	
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	ringbuf_t *q = t->rb;
	int j=0;
    while (!t->quit) {
        // u32 i;
        
        for (int i = 0; !ringbuf_is_full(q); i++) {
            if (j == 5) {
                break;
            }
            j++;
            struct burst_tx btx;
			btx.addr = 25000 + i;
			btx.len = 100;
            printf("RX pushed adrr %lld \n", btx.addr);
            ringbuf_sp_enqueue(q, (void *) &btx);
        }
            
    }
    return NULL;
}

int main(void)
{
    // ringbuf_t *rb = ringbuf_create((1 << 6));
    ringbuf_t *rb = ringbuf_create(16);
    if (!rb) {
        printf("Fail to create ring buffer.\n");
        return -1;
    }

    n_threads = 2;
	thread_data[0].cpu_core_id = 0; 
	thread_data[1].cpu_core_id = 1; 

    struct thread_data *t1 = &thread_data[0];
	struct thread_data *t2 = &thread_data[1];

    t1->rb = rb;
	t2->rb = rb;

    int status1 = pthread_create(&threads[0],
				NULL,
				thread_func_push,
				&thread_data[0]);
	if (status1) {
		printf("Thread1 creation failed.\n");
		return -1;
	}

	int status2 = pthread_create(&threads[1],
				NULL,
				thread_func_pop,
				&thread_data[1]);
	if (status2) {
		printf("Thread2 creation failed.\n");
		return -1;
	}

    // for (int i = 0; !ringbuf_is_full(r); i++)
    //     ringbuf_sp_enqueue(r, *(void **) &i);

    // for (int i = 0; !ringbuf_is_empty(r); i++) {
    //     void *obj;
    //     ringbuf_sc_dequeue(r, &obj);
    //     assert(i == *(int *) &obj);
    // }

    sleep(1);

    int i;

    for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);

    ringbuf_free(rb);
    return 0;
}
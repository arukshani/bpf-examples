# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := mem_design_1
BPF_TARGETS    := veth_kern
BPF_TARGETS    += nic_kern

# Define C-code objects USER_TARGETS needs
# USER_TARGETS_OBJS := spsc_queue.o memory.o ring/rte_ring.o
# USER_TARGETS_OBJS :=sts_queue/sts_queue.o memory.o
# USER_TARGETS_OBJS :=mpmc_queue.o memory.o

LDLIBS += -lpthread
LDLIBS += -lrte_mbuf
LDLIBS += -lrte_mempool
LDLIBS += -lrte_ring
LDLIBS += -lrte_eal

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk





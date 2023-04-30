# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := new_design
BPF_TARGETS    := veth_kern
BPF_TARGETS    += nic_kern

# Define C-code objects USER_TARGETS needs
# USER_TARGETS_OBJS := spsc_queue.o memory.o ring/rte_ring.o
# USER_TARGETS_OBJS :=sts_queue/sts_queue.o memory.o
# USER_TARGETS_OBJS :=mpmc_queue.o memory.o

LDLIBS += -lpthread

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

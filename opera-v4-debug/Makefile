# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := cloud_intel
BPF_TARGETS    := veth_kern
BPF_TARGETS    += nic_kern

LDLIBS += -lpthread

# USER_TARGETS_OBJS := map.o
USER_TARGETS_OBJS := map.o mpmc_queue.o memory.o

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := single_veth_4_threads_n1
BPF_TARGETS    := veth_kern
BPF_TARGETS    += nic_kern

# Define C-code objects USER_TARGETS needs
USER_TARGETS_OBJS := spsc_queue.o memory.o


LDLIBS += -lpthread

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

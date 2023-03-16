#!/bin/bash

echo 2| sudo tee /sys/class/net/enp65s0f0np0/napi_defer_hard_irqs
echo 1000 | sudo tee /sys/class/net/enp65s0f0np0/gro_flush_timeout

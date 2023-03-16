```
sudo ip link set dev enp65s0f0np0 xdpgeneric obj decap.o sec xdp_sock_1
sudo ip link set dev enp65s0f0np0 xdpgeneric off
sudo ip link list dev enp65s0f0np0
```

```
sudo tcpdump -i enp65s0f0np0 -j adapter_unsynced -w /tmp/node2_exp1.pcap
sudo tcpdump -i enp65s0f0np0 -w /tmp/node2_gre1.pcap
sudo tcpdump -i enp65s0f0np0 -w /tmp/node3_gre1.pcap
```

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

```
echo 2 | sudo tee /sys/class/net/enp65s0f0np0/napi_defer_hard_irqs
echo 200000 | sudo tee /sys/class/net/enp65s0f0np0/gro_flush_timeout
```
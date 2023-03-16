```
sudo ip link set dev enp65s0f0np0 xdpgeneric obj decap.o sec xdp_sock_1
sudo ip link set dev enp65s0f0np0 xdpgeneric off
sudo ip link list dev enp65s0f0np0
```
#!/bin/bash

sudo ip netns exec blue arp -s 192.168.1.2 02:10:30:0e:3b:ef
sudo ip netns exec red arp -s 192.168.1.2 0e:7c:c4:3a:39:12 
# sudo ip netns exec blue arp -s 192.168.1.1 ee:29:38:6f:21:7c
# sudo ip netns exec red arp -s 192.168.1.1 d2:64:1a:75:9b:68

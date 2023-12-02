#!/bin/bash

# echo $1 $2
sudo ip netns exec blue arp -i veth0 -s $1 $2
sudo ip netns exec red arp -i veth2 -s $1 $3
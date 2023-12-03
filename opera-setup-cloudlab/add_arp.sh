#!/bin/bash

# echo $1 $2 $3 $4
sudo ip netns exec $1 arp -i $2 -s $3 $4

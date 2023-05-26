#!/bin/sh

DIGIT=1
while [ $DIGIT -lt 32 ]
    do
        DIGIT=$(expr $DIGIT + 1)
        # echo $DIGIT
        # ping -c 2 192.168.1.$DIGIT
        sudo ip netns exec blue ping -c 5 192.168.1.$DIGIT
    done

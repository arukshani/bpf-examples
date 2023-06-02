#!/bin/sh

DIGIT=0
CONTROLLER=33
while [ $DIGIT -lt 32 ]
    do
        DIGIT=$(expr $DIGIT + 1)
        # echo $DIGIT
        # ping -c 2 192.168.1.$DIGIT
        ping -c 1 192.168.1.$DIGIT
    done

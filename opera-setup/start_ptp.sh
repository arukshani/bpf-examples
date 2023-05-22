#!/bin/sh

echo $1
nohup sudo ptp4l -i $1 -q > /dev/null 2>&1 &
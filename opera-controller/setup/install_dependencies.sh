#/bin/bash

sudo apt-get update 
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump
sudo apt install jq
sudo apt-get install linuxptp
sudo apt-get install libmnl-dev
sudo apt install m4
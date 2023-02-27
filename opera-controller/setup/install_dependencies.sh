#/bin/bash

sudo apt-get -y update 
sudo apt-get -y install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt-get -y install linux-tools-$(uname -r)
sudo apt-get -y install linux-headers-$(uname -r)
sudo apt-get -y install linux-tools-common linux-tools-generic
sudo apt-get -y install tcpdump
sudo apt-get -y install jq
sudo apt-get -y install linuxptp
sudo apt-get -y install libmnl-dev
sudo apt-get -y install m4
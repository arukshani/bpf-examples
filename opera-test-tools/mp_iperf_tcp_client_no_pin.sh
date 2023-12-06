#!/bin/bash

# Actual server is running on the other side on root

num_namespaces=0
server="10.1.0.2"
bandwidth="50000M"
nic_local_numa_node=$(cat /sys/class/net/ens4/device/numa_node)

for arg in "$@"
do
case $arg in
    -n|--number-of-ns)
        shift
        num_namespaces=$1
        shift
        ;;
esac
done

myArray=("blue" "red" "ns12" "ns13" "ns15" "ns16" "ns17" "ns18" "ns19" "ns20" "ns21" "ns22" "ns23" "ns24")

cpu_core_id=$(echo "63" | bc)
output=$(
for i in $(seq 0 $num_namespaces); do
    cpu_core_id=$(echo "$cpu_core_id+2" | bc)
    port=$(echo "5100+$i" | bc);
    echo $cpu_core_id
    numactl -N $nic_local_numa_node ip netns exec ${myArray[$i]} iperf3 -c $server -p $port -t 30 -f g -P 2 &
    # sudo taskset --cpu-list $cpu_core_id ip netns exec ${myArray[$i]} iperf3 -c $server -p $port -t 30 -f g -P 2 &
done
)

# echo $output
inter_out=$(echo $output| grep -o -P '(?<=sender).*?(?=receiver)')
# echo $inter_out
# inter_out_2=$(echo $inter_out| grep -oP 'SUM\K(?:(?!Gbits).)*')
inter_out_2=$(echo $inter_out| grep -oP 'SUM\s*\K(?:(?!\s+Gbits).)*')
# echo $inter_out_2
inter_out_3=$(echo $inter_out_2| grep -Po 'GBytes\s*[0-9.]*')
# echo $inter_out_3
inter_out_4=$(echo $inter_out_3 | grep -Po 'GBytes\s*\K\d\S*' | awk '{sum+=$1} END {print sum}')
echo $inter_out_4
# sender_total_tput=$(echo $inter_out_3 | grep -Po "(?=GBytes)[0-9]*" | awk '{sum+=$1} END {print sum}')
# echo $sender_total_tput

# '[0-9.]*(?= Gbits/sec)'
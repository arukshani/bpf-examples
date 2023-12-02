#!/bin/sh

NODE_INTERFACE=enp202s0f0np0;
NAMESPACE_ID=ns;
INSIDE_VETH=veth;
OUTSIDE_VETH=veth;


# for i in $(seq 1 10); do        
#     echo $i 
#     done

in_veth_number=0
out_veth_number=0
for i in $(seq 11 24); do 

    NEW_NAMESPACE_ID="$NAMESPACE_ID$i"
    echo $NEW_NAMESPACE_ID

    in_veth_number=`expr $i + 1`
    out_veth_number=`expr $in_veth_number + 10`

    INSIDE_VETH="vethin$in_veth_number"
    OUTSIDE_VETH="vethout$out_veth_number"
    echo $INSIDE_VETH
    echo $OUTSIDE_VETH

    sudo ip netns add $NEW_NAMESPACE_ID
    sudo ip link add $INSIDE_VETH type veth peer name $OUTSIDE_VETH
    sudo ip link set $INSIDE_VETH netns $NEW_NAMESPACE_ID
    sudo ip netns exec $NEW_NAMESPACE_ID ip link set dev $INSIDE_VETH up
    sudo ip link set dev $OUTSIDE_VETH up
    ip_addr=$(ip -f inet addr show $NODE_INTERFACE | awk '/inet / {print $2}')
    sudo ip netns exec $NEW_NAMESPACE_ID ip addr add $ip_addr dev $INSIDE_VETH
    sudo ip netns exec $NEW_NAMESPACE_ID ip link set arp off dev $INSIDE_VETH
    sudo ip netns exec $NEW_NAMESPACE_ID ethtool -K $INSIDE_VETH tx off
    sudo ip netns exec $NEW_NAMESPACE_ID ip link set $INSIDE_VETH mtu 3400
    sudo ip link set $OUTSIDE_VETH mtu 3400
done 
import argparse
import logging
import pandas as pd
from datetime import datetime
import plotly.graph_objs as go
import plotly
import matplotlib.pyplot as plt
import plotly.express as px

path = "/tmp/logs/2023-05-26_12-42-29/"

node1_data = pd.read_csv(path+"node-1-link-log.csv" ,sep=',', header=0,
        names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
node1_data['node_name'] = "node-1"
n1_tail_df = node1_data.tail(100)

node2_data = pd.read_csv(path+"node-2-link-log.csv" ,sep=',', header=0,
        names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
node2_data['node_name'] = "node-2"
n2_tail_df = node2_data.tail(100)

# node4_data = pd.read_csv(path+"node-4-link-log.csv" ,sep=',', header=0,
#         names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
# node4_data['node_name'] = "node-4"

# node11_data = pd.read_csv(path+"node-11-link-log.csv" ,sep=',', header=0,
#         names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
# node11_data['node_name'] = "node-13"

# node13_data = pd.read_csv(path+"node-13-link-log.csv" ,sep=',', header=0,
#         names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
# node13_data['node_name'] = "node-13"

print(n1_tail_df)
print(n2_tail_df)
# print(node4_data)
# print(node11_data)
# print(node13_data)

def get_us(rtt_ns):
    return rtt_ns*0.001

def hop_latency_5():
    c = 0
    for i in range(3, 19 + 1):
        if i % 2 != 0:
            index = i
            # print(i)
            # print(c)
            row1=node11_data.iloc[c]
            row2=node1_data.iloc[index]
            c = c +1
            # print("{}-{}".formar())
            hop_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
            print(hop_us)

def hop_latency_4():
    for i in range(0,9):
        # print(i)
        row1=node4_data.iloc[i]
        row2=node11_data.iloc[i]
        hop_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
        print(hop_us)

def hop_latency_3():
    c = 0
    for i in range(3, 19 + 1):
        if i % 2 != 0:
            index = i
            # print(i)
            # print(c)
            row1=node2_data.iloc[index]
            row2=node4_data.iloc[c]
            c = c +1
            # print("{}-{}".formar())
            hop_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
            print(hop_us)

def hop_latency_2():
    # i = 3
    c = 0
    for i in range(2,20,2):
        # print(i)
        # print(c)
        row1=node13_data.iloc[c]
        row2=node2_data.iloc[i]
        c = c +1
        hop_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
        print(hop_us)

def hop_latency_1():
    # i = 3
    c = 0
    for i in range(2,20,2):
        # print(i)
        # print(c)
        row1=node1_data.iloc[i]
        row2=node13_data.iloc[c]
        c = c +1
        hop_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
        print(hop_us)


#Meadured RTT
def rtt_us():
    for i in range(0,20,2):
        index = i
        row1=n1_tail_df.iloc[index]
        index = index+1
        row2=n1_tail_df.iloc[index]
        rtt_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
        print(rtt_us)

#Forward Path Latency
def fw_us():
    for i in range(0,20,2):
        index = i
        row1=n1_tail_df.iloc[index]
        row2=n2_tail_df.iloc[index]
        fw_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
        print(fw_us)

#Return Path Latency
def return_us():
    for i in range(1, 19 + 1):
        if i % 2 != 0:
            index = i
            # print(i)
            row1=n2_tail_df.iloc[index]
            row2=n1_tail_df.iloc[index]
            # print("{}-{}".formar())
            return_us = (row2['time_part_nsec'] - row1['time_part_nsec'])/1000
            print(return_us)

    # frames = [node1_data, node2_data, node13_data]
    # result = pd.concat(frames)
    # result.reset_index(drop=True, inplace=True)
    # print(result)


def forward_latency(node_name):
    node_data = pd.read_csv(path+node_name ,sep=',', header=0,
        names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
    # print(node_data.head(10))
    # print(node1_data.head(10))
    node1_forward = node1_data.loc[(node1_data['slot'] == 0)]
    node2_receive = node_data.loc[(node_data['slot'] == 2)]
    node1_forward.rename(columns={'node_ip': 'f_node_ip', 
                                    'slot': 'f_slot',
                                    'topo_arr': 'f_topo_arr',
                                    'next_node': 'f_next_node',
                                    'time_ns': 'f_time_ns',
                                    'time_part_sec': 'f_time_part_sec',
                                    'time_part_nsec': 'f_time_part_nsec'}, inplace=True)
    node2_receive.rename(columns={'node_ip': 'r_node_ip', 
                                    'slot': 'r_slot',
                                    'topo_arr': 'r_topo_arr',
                                     'next_node': 'r_next_node',
                                    'time_ns': 'r_time_ns',
                                    'time_part_sec': 'r_time_part_sec',
                                    'time_part_nsec': 'r_time_part_nsec'}, inplace=True)
    # print(node1_forward)
    # print(node2_receive)
    node1_forward.reset_index(drop=True, inplace=True)
    node2_receive.reset_index(drop=True, inplace=True)
    merged_df = node1_forward.merge(node2_receive, left_index=True, right_index=True)
    merged_df['forward__latency_ns'] = merged_df['r_time_part_nsec'] - merged_df['f_time_part_nsec']
    merged_df['forward__latency_us']= merged_df.forward__latency_ns.apply(get_us)
    print(merged_df[['f_topo_arr', 'r_topo_arr','forward__latency_us']])

def get_ping_rtt():
    # worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    # for index, row in worker_info.iterrows():
    # print(node1_data.head(10))
    forward_packets = node1_data.loc[(node1_data['slot'] == 0)]
    return_packets = node1_data.loc[(node1_data['slot'] == 2)]
    forward_packets.rename(columns={'node_ip': 'f_node_ip', 
                                    'slot': 'f_slot',
                                    'topo_arr': 'f_topo_arr',
                                    'next_node': 'f_next_node',
                                    'time_ns': 'f_time_ns',
                                    'time_part_sec': 'f_time_part_sec',
                                    'time_part_nsec': 'f_time_part_nsec'}, inplace=True)
    return_packets.rename(columns={'node_ip': 'r_node_ip', 
                                    'slot': 'r_slot',
                                    'topo_arr': 'r_topo_arr',
                                     'next_node': 'r_next_node',
                                    'time_ns': 'r_time_ns',
                                    'time_part_sec': 'r_time_part_sec',
                                    'time_part_nsec': 'r_time_part_nsec'}, inplace=True)
    forward_packets.reset_index(drop=True, inplace=True)
    return_packets.reset_index(drop=True, inplace=True)
    # print(forward_packets)
    # print(return_packets)
    merged_df = forward_packets.merge(return_packets, left_index=True, right_index=True)
    # print(merged_df[['r_time_part_nsec', 'f_time_part_nsec']].head(10))
    merged_df['rtt_ns'] = merged_df['r_time_part_nsec'] - merged_df['f_time_part_nsec']
    # print(merged_df[['rtt_ns']])
    merged_df['rtt_us']= merged_df.rtt_ns.apply(get_us)
    print(merged_df[['f_topo_arr','f_next_node', 'rtt_us']])
    # plt.plot(merged_df.index+1, merged_df["rtt_us"], label = "Node1")
    # plt.legend()
    # plt.xlabel('Packet Number', fontsize = 14)
    # plt.ylabel('Latency(us)', fontsize = 14)
    # plt.show()

def main(args):
    print(args)
    # if(args.analyze):
        # get_ping_rtt()
        # forward_latency('node-2-link-log.csv')
        # rtt_us()
        # fw_us()
        # return_us()
        # hop_latency_5()

def parse_args():
    parser = argparse.ArgumentParser(description='Analayze Data')
    parser.add_argument('--analyze', '-a', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)
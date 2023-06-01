import argparse
import logging
import pandas as pd
from datetime import datetime
import plotly.graph_objs as go
import plotly
import matplotlib.pyplot as plt
import plotly.express as px

path = "/tmp/logs/2023-06-01_16-39-55/"

node1_data = pd.read_csv(path+"node-1-link-log.csv" ,sep=',', header=0,
        names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
node1_data['node_name'] = "node-1"
# n1_tail_df = node1_data.tail(100)

# node2_data = pd.read_csv(path+"node-2-link-log.csv" ,sep=',', header=0,
#         names=["node_ip", "slot", "topo_arr", "next_node", "time_ns", "time_part_sec", "time_part_nsec"])
# node2_data['node_name'] = "node-2"
# n2_tail_df = node2_data.tail(100)


# print(n1_tail_df)
# print(n2_tail_df)


def main(args):
    for x in range(1, 33):
        node1_forward = node1_data.loc[(node1_data['topo_arr'] == x)]
        print("{}-{}".format(x,node1_forward['topo_arr'].count()))
    # print(args)
    # if(args.analyze):
        # get_ping_rtt()

def parse_args():
    parser = argparse.ArgumentParser(description='Analayze Data')
    parser.add_argument('--analyze', '-a', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)
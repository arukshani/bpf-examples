import subprocess
import binascii
import socket
import pandas as pd
import logging
import argparse

def add_arp_records(ip_of_running_node):
    worker_info = pd.read_csv('/home/dathapathu/emulator/github_code/all_worker_info.csv', header=None)
    for index, row in worker_info.iterrows():
        if (row[0] != ip_of_running_node):
            # print("add arp {} {} {}".format(row[0], row[5], row[6]))
            ip_without_subnet=row[0]
            remoteCmd = './add_arp.sh {} {} {}'.format(ip_without_subnet, row[5], row[6])
            proc = subprocess.run(remoteCmd, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8').strip()

def parse_args():
    parser = argparse.ArgumentParser(description='IP of the running node')
    parser.add_argument('ip_of_node')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    # print('Arguments: {}'.format(args.ip_of_node))
    add_arp_records(args.ip_of_node)

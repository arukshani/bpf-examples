import subprocess
import binascii
import socket
import pandas as pd
import logging
import argparse

NSes = ["blue", "red", "ns12", "ns13", "ns15", "ns16", "ns17", "ns18", "ns19", "ns20", "ns21", "ns22", "ns23", "ns24"]

def add_arp_records(filename):
    arp_info = pd.read_csv(filename, header=None)
    for i in range(len(NSes)):
        for index, row in arp_info.iterrows():
            # print("{}, {}, {}".format(NSes[i], row[2], str(NSes[i]) == str(row[2])))
            if (str(NSes[i]) == str(row[2]).strip()):
                # print("hello")
                remoteCmd = './add_arp.sh {} {} {} {}'.format(row[2], row[3], row[4], row[5])
                # print(remoteCmd)
                proc = subprocess.run(remoteCmd, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8').strip()
                print(proc)

def parse_args():
    parser = argparse.ArgumentParser(description='filename')
    parser.add_argument('filename')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    # print('Arguments: {}'.format(args.ip_of_node))
    add_arp_records(args.filename)

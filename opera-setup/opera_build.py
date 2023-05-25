import os
import argparse
import subprocess
import pickle
import logging
import pandas as pd

def start_opera_nic():
    worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    for index, row in worker_info.iterrows():
        print("===================START OPERA NIC==={}=======================".format(row[7]))
        remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./start_opera.sh {} {} {}'.format(row[6], row[7], row[0], row[7], row[5])
        proc = subprocess.run(remoteCmd, shell=True)

def pull_changes():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            print("===================PULL==={}=======================".format(worker['host']))
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./pull_opera.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def clean_opera():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            print("===================CLEAN==={}=======================".format(worker['host']))
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./clean_opera.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def build_opera():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            print("===================MAKE==={}=======================".format(worker['host']))
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./make_opera.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)


def main(args):
    # print(args)
    if(args.make):
        build_opera()
    
    if(args.clean):
        clean_opera()

    if(args.pull):
        pull_changes()

    if(args.start):
        start_opera_nic()

def parse_args():
    parser = argparse.ArgumentParser(description='Start and stop PTP on worker nodes')
    parser.add_argument('--make', '-m', action='store_true')
    parser.add_argument('--clean', '-c', action='store_true')
    parser.add_argument('--pull', '-p', action='store_true')
    parser.add_argument('--start', '-s', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)
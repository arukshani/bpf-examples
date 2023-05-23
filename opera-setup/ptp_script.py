import os
import argparse
import subprocess
import pickle
import logging
import pandas as pd

def stop_ptp():
    # print("Kill PTP")
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            print("===================KILL PTP==={}=======================".format(worker['host']))
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./stop_ptp.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def start_ptp():
    worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    for index, row in worker_info.iterrows():
        print("===================START PTP==={}=======================".format(row[6]))
        remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./start_ptp.sh {}'.format(row[6], row[7], row[4])
        proc = subprocess.run(remoteCmd, shell=True)

def main(args):
    # print(args)
    if(args.start):
        start_ptp()
    
    if(args.stop):
        stop_ptp()

def parse_args():
    parser = argparse.ArgumentParser(description='Start and stop PTP on worker nodes')
    parser.add_argument('--start', '-s', action='store_true')
    parser.add_argument('--stop', '-k', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)


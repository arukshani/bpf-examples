import os
import argparse
import subprocess
import pickle
import logging

def stop_ptp():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./stop_ptp.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def start_ptp():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./start_ptp.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def main(args):
    # print(args)
    if(args.start == 1):
        start_ptp()
    
    if(args.stop == 1):
        stop_ptp()

def parse_args():
    parser = argparse.ArgumentParser(description='Start and stop PTP on worker nodes')
    parser.add_argument('--start', '-s', type=int, default=0)
    parser.add_argument('--stop', '-k', type=int, default=0)
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)


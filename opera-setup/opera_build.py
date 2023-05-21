import os
import argparse
import subprocess
import pickle
import logging

def pull_changes():
    print("Pull Changes")
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./pull_opera.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def clean_opera():
    print("Clean Opera")
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./clean_opera.sh'.format(worker['username'],worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def build_opera():
    print("Make Opera")
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
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

def parse_args():
    parser = argparse.ArgumentParser(description='Start and stop PTP on worker nodes')
    parser.add_argument('--make', '-m', action='store_true')
    parser.add_argument('--clean', '-c', action='store_true')
    parser.add_argument('--pull', '-p', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)
import os
import argparse
import subprocess
import pickle
import logging
import pandas as pd
import datetime

def move_logs(directory_name):
    localCmd = 'mv /tmp/logs/*.csv {}'.format(directory_name)
    proc = subprocess.run(localCmd, shell=True)

def create_directory():
    log_dir = os.path.join("/tmp/logs/", datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    os.makedirs(log_dir)
    return log_dir

def collect_logs():
    worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    for index, row in worker_info.iterrows():
        print("===================Collect Logs From:==={}=======================".format(row[7]))
        localCmd = 'scp -r {}@{}:/tmp/{}-log.csv /tmp/logs'.format(row[6], row[7], row[7])
        proc = subprocess.run(localCmd, shell=True)

def rename_logs():
    worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    for index, row in worker_info.iterrows():
        print("===================Rename Logs:==={}=======================".format(row[7]))
        remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./rename_logs.sh {}'.format(row[6], row[7], row[7])
        proc = subprocess.run(remoteCmd, shell=True)

def main(args):
    # print(args)
    if(args.collect):
        rename_logs()
        collect_logs()
        directory_name=create_directory()
        move_logs(directory_name)
        
def parse_args():
    parser = argparse.ArgumentParser(description='Data Collection')
    parser.add_argument('--collect', '-c', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    args = parse_args()
    logging.info('Arguments: {}'.format(args))
    main(args)
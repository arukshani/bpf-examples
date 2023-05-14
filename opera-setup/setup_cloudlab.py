import os
import subprocess
import ipaddress
import pandas as pd
import pickle
import json 
import constant

USER = os.environ['USER']
IDENTITY_FILE = '/users/{}/.ssh/{}_cloudlab.pem'.format(USER, USER)

def setup_workers():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./setup_worker.sh'.format(worker['username'], worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def export_environs():
    node_info = pd.read_csv('/tmp/all_nodes.csv', header=None)
    workers = []
    master_ip = get_master_ip()
    for index, row in node_info.iterrows():
        #TODO: Get interface names nad remote ips
        node = {'ifname_remote': 'eno33np0', 
                        'ifname_local': 'enp65s0f0np0',
                        'host': row[0],
                        'ip_lan': row[1],
                        'ip_wan': '', 
                        'key_filename': IDENTITY_FILE,
                        'username': USER}
        if  row[1] != master_ip:
            workers.append(node)
        else:
            with open('/tmp/master.pkl', 'wb') as f:  
                pickle.dump([node], f)
    with open('/tmp/workers.pkl', 'wb') as f:  
        pickle.dump(workers, f)

def get_nodeinfo():
    node_info = pd.read_csv('/tmp/all_nodes.csv', header=None)
    return node_info

def create_ssh_config():
    node_info = get_nodeinfo()
    ssh_config = ''
    for index, row in node_info.iterrows():
        if  row[1] != get_master_ip():
            ssh_config += ('Host {} \n'
                    '    HostName {} \n'
                    '    User {} \n'
                    '    IdentityFile {} \n').format(row[0],row[1], USER, IDENTITY_FILE)
    with open('/users/{}/.ssh/config'.format(os.environ['USER']), 'w') as f:
        f.write(ssh_config)

def get_master_ip():
    cmd = "ip -4 addr show enp65s0f0np0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'" #interface name assumed to be 'ens1f1'
    master_local_ip = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8').strip()
    return master_local_ip

def find_worker_nodes():
    master_local_ip = get_master_ip()
    network_prefix = '.'.join(master_local_ip.split('.')[0:-1])
    cmd = '''nmap -sP %s.* | awk '/node/{print substr($5, 1, length($5)-0) \",\" substr($6,2, length($6)-2)}\' > /tmp/all_nodes.csv'''%(network_prefix)
    subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8').strip()

def install_packges():
    proc = subprocess.run("sudo apt-get update", shell=True)
    assert(proc.returncode == 0)
    proc = subprocess.run("sudo apt install nmap", shell=True)
    assert(proc.returncode == 0)

def main():
    # check if identity file exists & works
    if not os.path.isfile(IDENTITY_FILE):
        print('Could not find identify file: {}. Please add it to this machine to run cloudlab setup'.format(IDENTITY_FILE))
        exit(1)
    
if __name__ == '__main__':
    main()
    # install_packges()
    # find_worker_nodes()
    # create_ssh_config()
    # export_environs()
    setup_workers()
    
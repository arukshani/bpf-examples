import os
import subprocess
import ipaddress
import pandas as pd
import pickle
import json 
import constant
import binascii
import socket

USER = os.environ['USER']
IDENTITY_FILE = '/users/{}/.ssh/{}_cloudlab.pem'.format(USER, USER)

def add_arp_records_for_single_node():
    node_info = pd.read_csv('/tmp/node_32_info.csv', header=None)
    worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    for index, row in node_info.iterrows():
        print("--- Add ARP records for {} ---".format(row[0]))
        for c_index, c_row in worker_info.iterrows():
            # print("all to all {} {}".format(c_row[0], c_row[1]))
            if (row[0] != c_row[0]):
                remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./add_arp.sh {} {}'.format(row[6], row[7], c_row[0], c_row[3])
                proc = subprocess.run(remoteCmd, shell=True)

###################################################

def copy_worker_info():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'scp -o StrictHostKeyChecking=no /tmp/all_worker_info.csv {}:/tmp'.format(worker['host'])
            proc = subprocess.run(remoteCmd, shell=True)

def add_arp_records():
    worker_info = pd.read_csv('/tmp/all_worker_info.csv', header=None)
    for index, row in worker_info.iterrows():
        print("--- Add ARP records for {} ---".format(row[0]))
        for c_index, c_row in worker_info.iterrows():
            # print("all to all {} {}".format(c_row[0], c_row[1]))
            if (row[0] != c_row[0]):
                remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./add_arp.sh {} {}'.format(row[6], row[7], c_row[0], c_row[3])
                proc = subprocess.run(remoteCmd, shell=True)

def get_worker_mac():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./get_mac.sh {}'.format(worker['username'], worker['host'], worker['ip_lan'])
            stdout = subprocess.run(remoteCmd, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8').strip()
            hex_val="0x{}".format(binascii.hexlify(socket.inet_aton(worker['ip_lan'])).decode('ascii'))
            stdout = stdout + ",{},{},{}".format(worker['username'], worker['host'], hex_val)
            with open("/tmp/all_worker_info.csv", "a") as myfile:
                myfile.write(stdout + "\n")
            

def setup_workers():
    with open('/tmp/workers.pkl','rb') as f:  
        workers = pickle.load(f)
        for worker in workers:
            remoteCmd = 'ssh -o StrictHostKeyChecking=no {}@{} "bash -s" < ./setup_worker.sh {}'.format(worker['username'], worker['host'], worker['ip_lan'])
            proc = subprocess.run(remoteCmd, shell=True)

def export_environs():
    node_info = pd.read_csv('/tmp/all_nodes.csv', header=None)
    workers = []
    master_ip = get_master_ip()
    for index, row in node_info.iterrows():
        #TODO: Get interface names nad remote ips
        node = {'ifname_remote': '', 
                        'ifname_local': '',
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
    cmd = "ip -4 addr show enp65s0f0np0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'" #interface name assumed to be 'enp65s0f0np0'
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

    #First run this ++++++SECTION 1++++++++++++++++++++++++++++++++++++
    install_packges()
    find_worker_nodes() # Maunally check whether all workers are there if not add them

    #Then run this +++++++SECTION 2++++++++++++++++++++++++++++++++++++
    create_ssh_config()
    export_environs()
    setup_workers()
    get_worker_mac()
    add_arp_records()
    copy_worker_info()

    #+++++++++++++ADDITIONAL FOR SPECIAL CASES+++++++++++++++++++++++++
    # add_arp_records_for_single_node()
    
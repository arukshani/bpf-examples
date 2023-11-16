import subprocess
import binascii
import socket

def get_worker_mac():
    remoteCmd = './get_mac.sh'
    stdout = subprocess.run(remoteCmd, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8').strip()
    hex_val_lan_ip="0x{}".format(binascii.hexlify(socket.inet_aton(stdout.partition(',')[0])).decode('ascii'))
    stdout = stdout + ",{}".format(hex_val_lan_ip)
    # print(stdout)
    with open("/home/dathapathu/emulator/github_code/all_worker_info.csv", "a") as myfile:
        myfile.write(stdout + "\n")

    
if __name__ == '__main__':
    get_worker_mac()


### Master Node
```
scp ~/.ssh/rukshani_cloudlab.pem rukshani@ip:~/.ssh/
cd /opt
git clone https://github.com/arukshani/bpf-examples.git
cd bpf-examples/opera-setup/
./setup_master.sh
python3 setup_cloudlab.py
```

### Maunally check whether all workers are there if not add them
```
cat /tmp/all_nodes.csv
```
<!-- ##### Comment SECTION1 and uncomment SECTION2 and run the script again

```
python3 setup_cloudlab.py
``` -->

### PTP Start and Kill
```
python3 ptp_script.py -s 
python3 ptp_script.py -k 
```

### Make, Clean, Pull and Start Opera Code
```
python3 opera_build.py -m //make
python3 opera_build.py -c //clean
python3 opera_build.py -p //pull
python3 opera_build.py -s //start
```

### All worker info fileds
```
local_IP,local_interface,node_mac,veth_mac,ptp_interface,ptp_clock_name,username,node_name,ip_in_hex
```

### Testing Nodes (Not needed)
```
./test_nodes.sh 
```

### setup a single node (This is not needed)
```
Restart the node
Run setup_worker.sh on the node (eg: /bin/bash setup_worker.sh 192.168.1.32)
Create an copy the single record to node_XX_info.csv file under /tmp in controller
Copy /tmp/all_worker_info.csv to the node
Run setup_cloudlab.py with just 'add_arp_records_for_single_node()' function
```


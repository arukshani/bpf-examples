
# Master Node
```
scp ~/.ssh/rukshani_cloudlab.pem rukshani@ip:~/.ssh/
cd /opt
git clone https://github.com/arukshani/bpf-examples.git
cd bpf-examples/opera-setup/
./setup_master.sh
python3 setup_cloudlab.py
```

# Maunally check whether all workers are there if not add them
# Comment SECTION1 and uncomment SECTION2 and run the script again

```
python3 setup_cloudlab.py
```

```
python3 ptp_script.py -s 1
python3 ptp_script.py -k 1
```
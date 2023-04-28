import socket

UDP_IP = "192.168.1.2"
UDP_PORT = 8000
# MESSAGE = ""

print("UDP target IP:", UDP_IP)
print ("UDP target port:", UDP_PORT)
# print ("message:", MESSAGE)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

for x in range(0, 10):
    MESSAGE = "Msg {}\n".format(str(x))
    sock.sendto(bytes(MESSAGE, "utf-8"), (UDP_IP, UDP_PORT))
import socket
import sys

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('192.168.1.2', 10000)
message = 'This is the message.  It will be repeated.'

try:

    for x in range(0, 8000):
        # Send data
        # print >>sys.stderr, 'sending "%s"' % message
        sent = sock.sendto(bytes(message, "utf-8"), server_address)

        # Receive response
        # print >>sys.stderr, 'waiting to receive'
        # data, server = sock.recvfrom(4096)
        # print >>sys.stderr, 'received "%s"' % data

finally:
    # print >>sys.stderr, 'closing socket'
    sock.close()
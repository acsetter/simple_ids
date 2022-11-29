#!/usr/bin/env python
"""
A simple Linux IDS that filters ICMP packets
and sends the packet info to a server via TCP
"""

import subprocess
import socket

SERVER = "10.10.50.2"
PORT = 9000


def main():
    print(f"IDS sending alerts to {SERVER} on port {PORT}")
    # Run and listen to command `~$ sudo tcpdump icmp -n -l`
    with subprocess.Popen(['sudo', 'tcpdump', 'icmp', '-n', '-l'],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          bufsize=1, universal_newlines=True) as p:
        for line in p.stdout:
            # filter echo requests only (ignore replies)
            if line.find("echo request") > -1:
                # establish TCP connection with server/monitor
                sock = socket.create_connection((SERVER, PORT))
                try:
                    # send the packet info
                    sock.sendall(line.encode())
                finally:
                    print(line, end='')
                    sock.close()


if __name__ == '__main__':
    main()

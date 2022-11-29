#!/usr/bin/env python
"""
A Simple IDS monitoring/receiver program that pushes potential
security risk info as windows notifications via a TCP connection.
"""

import socket
from win10toast import ToastNotifier

SERVER = "10.10.50.2"
PORT = 9000
SIZE = 1024


def main():
    # create a socket connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((SERVER, PORT))
    sock.listen(1)
    print(f"IDS Monitor listening on port {PORT}")
    toast = ToastNotifier()

    while True:
        c, p = sock.accept()
        data = c.recv(SIZE)  # wait for IDS to send something...
        output = ""
        while len(data) > 0:
            # decode received data
            output += data.decode()
            data = c.recv(SIZE)
        print(output, end='')
        alert = parse_alert(output)
        # display packet info as a windows notification
        toast.show_toast(f"IDS Alert: {alert['type']}",
                         f"{alert['src']} --> {alert['dst']}\n"
                         f"{alert['time']} | {alert['seq']} | {alert['len']}",
                         duration=5, icon_path="alert.ico", threaded=True)


def parse_alert(alert: str) -> dict:
    """
    Parse packet info (ICMP only but can be extended)
    :param alert: (str) packet info to parse
    :return: (dict) parsed packet info
    """
    i_list = alert.split(': ')
    time, proto, src, _, dst = tuple(i_list[0].split(' '))
    a_type, a_id, a_seq, a_len = tuple(i_list[1].split(', '))

    return {
        "time": time[0:time.find('.')],
        "proto": proto,
        "src": src,
        "dst": dst,
        "type": a_type,
        "id": a_id,
        "seq": a_seq,
        "len": a_len
    }


if __name__ == '__main__':
    main()

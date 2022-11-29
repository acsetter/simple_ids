# Simple Linux IDS
> A simple intrusion detection system (IDS) that filters ICMP packet via [tcpdump](https://www.tcpdump.org/) and send the packet info to a windows-specific monitoring/receiving program via TCP.

## Getting Started
* In both `ids.py` and `ids_monitoring.py`, change the `SERVER` var to the local IP of the Windows machine.
* On the Linux machine ensure [Python3 is installed](https://phoenixnap.com/kb/how-to-install-python-3-ubuntu).
```
sudo python3 PATH/TO/ids.py
```

* On Windows, ensure python 3 is installed as well as [win10toast](https://pypi.org/project/win10toast/).
```
python3 PATH/TO/ids_monitor.py
```

* With both endpoints running, try pinging the Linux machine.
```
ping <IP/HOSTNAME> -n 1
```

* If successful, a Windows notification should appear.

![image](https://user-images.githubusercontent.com/39916941/204545620-64a82e0a-1ad7-46c3-8ec0-8576a600d43d.png)
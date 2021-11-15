# _*_ encoding=utf-8 _*_
# by SkyBlueEternal

from io import StringIO
from scapy.all import *

"""
    # https://mp.weixin.qq.com/s/GUab_Cz-PlEUJXNuyiVTLQ
    1. run "ifconfig", show wlan0.
    2. run "airmon-ng start wlan0". 
    3. run "ifconfig" interface name is wlan0mon.
    4. run "python3 -m pip scapy".
    5. run "python3 script.py"
"""


def packet_Handler(pkt):
    capture = StringIO()
    save_stdout = sys.stdout
    sys.stdout = capture
    pkt.show()
    sys.stdout = save_stdout
    log = capture.getvalue()
    # filter protocol.
    if "Multi-AP Policy Config" in log:
        print(log)
    else:
        pass


def __flow_separa__(packet):
    # filter SSID.
    if "info='Guest'" in str(packet.show):
        return packet
    else:
        pass


if __name__ == '__main__':
    sniff(
        filter='',
        prn=lambda p: packet_Handler(p),
        lfilter=lambda p: __flow_separa__(p),
        iface='wlan0mon'
    )

# wifi-Mesh-monitor(wifi 空口监控技术) 【2021.11.15】

# 简介
  拜读大佬的文章 https://mp.weixin.qq.com/s/GUab_Cz-PlEUJXNuyiVTLQ ，然后分析写的Demo。
# 测试环境
  系统：Kali
  无线网卡：NT-G450M
# 测试记录
```python
# ifconfig
eth0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 00:0c:29:a1:b7:79  txqueuelen 1000  (Ethernet)
        RX packets 2  bytes 484 (484.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13  bytes 1430 (1.3 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8  bytes 400 (400.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8  bytes 400 (400.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether b6:f6:c7:c1:af:e5  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        
# airmon-ng start wlan0

Found 2 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    535 NetworkManager
   1344 wpa_supplicant

PHY     Interface       Driver          Chipset

phy0    wlan0           rt2800usb       NetGear, Inc. WNDA4100
                (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
                (mac80211 station mode vif disabled for [phy0]wlan0)
                
# python3 main.py

```
# 脚本注解
```
1. sniff()是嗅探器，嗅探无线网卡范围内的所有广播。
2. __flow_separa__()是流分离器，能够分离SSID等信息,如果在这段的恶意载荷可以直接分离。
3. packet_Handler()是包解析器，能够在分流器的后面捕获属性和值，并且用于判恶意的值。
```

```python
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
    if "info='kwai-staff'" in str(packet.show):
        return packet
    else:
        pass


if __name__ == '__main__':
    # 启动监听
    sniff( 
        filter='',
        prn=lambda p: packet_Handler(p),
        lfilter=lambda p: __flow_separa__(p),
        iface='wlan0mon'
    )

```

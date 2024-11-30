from dataclasses import dataclass
from typing import Optional
from scapy.all import rdpcap, Packet, IP, TCP
from scapy.layers import inet as scapy_layers
from pprint import pprint


@dataclass
class IpFlowId:
    """A way to identify IP flows"""
    src_addr: str
    dst_addr: str


@dataclass
class TcpFlowId:
    """A way to identify TCP connections"""
    src_port: int
    dst_port: int
    ip: IpFlowId


class Flow:
    def __init__(self, id: IpFlowId, first_packet: Packet):
        self.id = id
        self.packets = [first_packet]


flows: list[Flow] = []

def find_flow(flow_id: IpFlowId) -> Optional[Flow]:
    for flow in flows:
        if flow_id == flow.id:
            return flow
    return None

sessions = rdpcap("test.pcapng").sessions()

for session_name in sessions:
    if "TCP" not in session_name:
        continue
    data = b""
    for packet in sessions[session_name]:
        if "P" in packet[TCP].flags:
            data += packet[TCP].load

    if b"KEYLOGGERDETECTSTRING" in data:
        print(f"Detected Liragbr/keylogger! {session_name}")

# for packet in rdpcap("Liragbr.pcapng"):
#     if IP not in packet:
#         continue
#     ip_flow_data = IpFlowId(packet[IP].src, packet[IP].dst)
#     if TCP in packet:
#         tcp_flow_data = TcpFlowId(packet[TCP].sport, packet[TCP].dport, ip_flow_data)
#     pprint(packet)

from dataclasses import dataclass
from typing import Optional
from scapy.all import rdpcap, Packet, bind_layers  # type: ignore
from scapy.sendrecv import sniff
from scapy.sessions import TCPSession
from scapy.fields import StrField
from scapy.layers.inet import IP, TCP
from pprint import pprint


@dataclass
class FlowId:
    """A way to identify flows/streams/whatever you want to call them"""

    protocol: str
    """The application layer protocol's name"""
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int


class Flow:
    def __init__(self, id: FlowId, first_packet: Packet):
        self.id = id
        self.packets = [first_packet]
        self.deltas: list[float] = []

    def add_packet(self, packet: Packet):
        prev = self.packets[-1]
        self.packets.append(packet)
        self.deltas.append(float(packet.time) - float(prev.time))


flows: list[Flow] = []


def find_flow(flow_id: FlowId) -> Optional[Flow]:
    for flow in flows:
        if flow_id == flow.id:
            return flow
    return None


pcap = "ftp_only.pcapng"  # "Liragbr.pcapng"

sessions = rdpcap(pcap).sessions()

# print("\n".join(sessions.keys()))

# pprint(TCP(b"TYPE A"))

# for session_name in sessions:
#     if "TCP" not in session_name:
#         continue
#     data = b""
#     for packet in sessions[session_name]:
#         pprint(packet)
#         exit(0)
#         if "P" in packet[TCP].flags:
#             data += packet[TCP].load

#     if b"KEYLOGGERDETECTSTRING" in data:
#         print(f"Detected Liragbr/keylogger! {session_name}")


class SMTP(Packet):
    name = "SMTP"
    fields_desc = [StrField("raw", b"")]

    @classmethod
    def tcp_reassemble(cls, data: bytes, _metadata, _session):
        return SMTP(raw=data)


class FTPRequest(Packet):
    """FTP control port requests"""

    name = "FTP"
    fields_desc = [StrField("cmd", b""), StrField("args", b"")]

    @classmethod
    def tcp_reassemble(cls, data: bytes, metadata, session):
        data = data.rstrip(b"\r\n")
        cmd, *args = data.split(b" ")
        return FTPRequest(cmd=cmd, args=b" ".join(args))


WINDOW = 4
DETECTION_THRESHOLD = 0.2

def detect_keylogger(flow: Flow):
    # Some messages may be split up across multiple packets, at least with SMTP
    deltas = [delta for delta in flow.deltas if delta < 3.0]
    if len(deltas) >= WINDOW:
        deltas = flow.deltas[-WINDOW:]
        mean = sum(deltas) / len(deltas)
        variance = sum((x - mean) ** 2 for x in deltas) / len(deltas)
        print("Variance:", variance)
        if variance < DETECTION_THRESHOLD:
            print("Keylogger detected!", flow.id)
            exit(1)


# Unencrypted
bind_layers(TCP, SMTP, dport=25)
# Uses SSL
bind_layers(TCP, SMTP, dport=465)
# Uses TLS
bind_layers(TCP, SMTP, dport=587)
# Control port only. Not encrypted
bind_layers(TCP, FTPRequest, dport=21)

RECOGNIZED_PROTOCOLS: list[type[Packet]] = [SMTP, FTPRequest]

# for packet in sniff(offline=pcap, session=TCPSession):
for packet in sniff(iface="eth0", session=TCPSession):
    for protocol in RECOGNIZED_PROTOCOLS:
        if protocol in packet:
            if protocol == FTPRequest and packet[FTPRequest].cmd != b"STOR":
                # For now, ignore anything that isn't storing data
                continue
            flow_id = FlowId(
                protocol=str(protocol),
                src_addr=packet[IP].src,
                dst_addr=packet[IP].dst,
                src_port=packet[TCP].sport,
                dst_port=packet[TCP].dport,
            )
            flow = find_flow(flow_id)
            if flow is not None:
                flow.add_packet(packet)
                detect_keylogger(flow)
            else:
                flow = Flow(flow_id, packet)
                flows.append(flow)
            break

for flow in flows:
    print("------ Flow", flow.id, "-----")
    print(flow.deltas)
    pprint(flow.packets)
print("done")

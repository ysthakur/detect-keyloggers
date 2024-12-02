import argparse
from dataclasses import dataclass
from typing import Optional
from scapy.all import Packet, bind_layers  # type: ignore
from scapy.sendrecv import sniff
from scapy.sessions import TCPSession
from scapy.fields import StrField
from scapy.layers.inet import IP, TCP
from pprint import pprint


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


WINDOW = 4
DETECTION_THRESHOLD = 0.2

def detect_keylogger(flow: Flow):
    # Some messages may be split up across multiple packets, at least with SMTP
    deltas = [delta for delta in flow.deltas if delta < 3.0]
    if len(deltas) >= WINDOW:
        deltas = deltas[-WINDOW:]
        mean = sum(deltas) / len(deltas)
        variance = sum((x - mean) ** 2 for x in deltas) / len(deltas)
        print("Variance:", variance)
        if variance < DETECTION_THRESHOLD:
            print("Keylogger detected!", flow.id)
            exit()

def process_packet(packet: Packet):
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


# Unencrypted
bind_layers(TCP, SMTP, dport=25)
# Uses SSL
bind_layers(TCP, SMTP, dport=465)
# Uses TLS
bind_layers(TCP, SMTP, dport=587)
# Control port only. Not encrypted
bind_layers(TCP, FTPRequest, dport=21)

RECOGNIZED_PROTOCOLS: list[type[Packet]] = [SMTP, FTPRequest]

parser = argparse.ArgumentParser(
    prog="detect_keyloggers", description="""Either --file or --iface must be given"""
)
parser.add_argument("-f", "--file", help=".pcap or .pcapng file to get packets from")
parser.add_argument("-i", "--iface", help="Interface to sniff")

args = parser.parse_args()

if args.file and args.iface:
    print("Only one of --file and --iface should be provided")
    exit(1)

sniff_args = {
    "prn": process_packet,
    "session": TCPSession,
    "store": 0
}

if args.file:
    sniff(offline=args.file, **sniff_args)
elif args.iface:
    sniff(iface=args.iface, **sniff_args)
else:
    print("Either --file or --iface must be provided")
    exit(1)

for flow in flows:
    print("------ Flow", flow.id, "-----")
    print(flow.deltas)
    pprint(flow.packets)
print("done")

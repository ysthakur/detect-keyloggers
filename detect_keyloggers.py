import argparse
from dataclasses import dataclass
from typing import Optional
from scapy.all import Packet, bind_layers, conf  # type: ignore
from scapy.sendrecv import sniff
from scapy.sessions import TCPSession
from scapy.fields import StrField
from scapy.layers.inet import IP, TCP
from pprint import pprint

conf.use_npcap = True


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


# Unencrypted
bind_layers(TCP, SMTP, dport=25)
# Uses SSL
bind_layers(TCP, SMTP, dport=465)
# Uses TLS
bind_layers(TCP, SMTP, dport=587)
# Control port only. Not encrypted
bind_layers(TCP, FTPRequest, dport=21)

RECOGNIZED_PROTOCOLS: list[type[Packet]] = [SMTP, FTPRequest, TCP]

parser = argparse.ArgumentParser(prog="detect_keyloggers")
parser.add_argument("-f", "--file", help=".pcap or .pcapng file to get packets from")
parser.add_argument(
    "-i",
    "--iface",
    help="Interface to sniff. If not provided, all interfaces will be sniffed",
)
parser.add_argument(
    "-w",
    "--window",
    help="How many previous packets to look at",
    default=3,
    type=int,
)
parser.add_argument(
    "-v",
    "--variance",
    help="Maximum variance in consecutive delay latencies to flag a packet",
    default=0.2,
    type=float,
)
parser.add_argument(
    "-I",
    "--ignore-interval",
    help="Ignore a packet sent these many seconds after the previous one",
    default=0.2,
    type=float,
)
parser.add_argument(
    "-s",
    "--detect-string",
    help="String used to detect Liragbr/keylogger, which sends messages unencrypted",
    default="keyloggerdetect",
)
args = parser.parse_args()

if args.file and args.iface:
    print("Only one of --file and --iface should be provided")
    parser.print_help()
    parser.exit(1)

window: int = args.window
detect_threshold: float = args.variance
ignore_interval: float = args.ignore_interval
detect_string: str = args.detect_string


def detect_keylogger(flow: Flow):
    if flow.id.protocol == "TCP":
        # Liragbr/keylogger is detected based on packet contents, not deltas
        data = "".join(packet[TCP].load for packet in flow.packets)
        print(f"Full string: {data}")
        if detect_string in data:
            print("Liragbr/keylogger detected!", flow.id)
            exit()
        return

    # Some messages may be split up across multiple packets, at least with SMTP
    deltas = [delta for delta in flow.deltas if delta < ignore_interval]
    if len(deltas) >= window:
        deltas = deltas[-window:]
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
            if protocol == TCP and "P" not in packet[TCP].flags:
                # Liragbr/keylogger sets the push flag when sending keys
                continue
            flow_id = FlowId(
                protocol=str(packet.getlayer(protocol).name),
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
            print(f"Received {flow_id.protocol} packet: {packet}")
            break


if args.file:
    sniff(offline=args.file, prn=process_packet, session=TCPSession, store=0)
elif args.iface:
    sniff(iface=args.iface, prn=process_packet, session=TCPSession, store=0)
else:
    sniff(prn=process_packet, session=TCPSession, store=0)

for flow in flows:
    print("------ Flow", flow.id, "-----")
    print(flow.deltas)
    pprint(flow.packets)
print("done")

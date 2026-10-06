"""
PCAP Generation Tool for DPI Engine Testing.
Generates synthetic network traffic including TLS, HTTP, and DNS packets
for deep packet inspection functional testing.
Uses zero dependencies (struct packing) for portability.
"""

import logging
import random
import struct
from dataclasses import dataclass
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class NetworkEndpoint:
    """Represents a network node with MAC and IP addresses."""
    mac: str
    ip: str


class PCAPWriter:
    """Handles the writing of raw packets into a pcap format file."""
    
    MAGIC_NUMBER = 0xA1B2C3D4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4

    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, "wb")
        self.timestamp = 1700000000
        self._write_global_header()

    def _write_global_header(self) -> None:
        """Writes the pcap file global header."""
        header = struct.pack(
            "<IHHIIII",
            self.MAGIC_NUMBER,
            self.VERSION_MAJOR,
            self.VERSION_MINOR,
            0,
            0,
            65535,
            1
        )
        self.file.write(header)

    def write_packet(self, data: bytes) -> None:
        """Writes an individual packet with a timestamp header."""
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        
        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self) -> None:
        """Closes the underlying file descriptor."""
        self.file.close()


class PacketBuilder:
    """Static utility class for constructing network protocol headers."""

    @staticmethod
    def create_ethernet_header(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
        return (
            bytes.fromhex(dst_mac.replace(":", ""))
            + bytes.fromhex(src_mac.replace(":", ""))
            + struct.pack(">H", ethertype)
        )

    @staticmethod
    def create_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
        version_ihl = 0x45
        tos = 0
        total_len = 20 + payload_len
        ident = random.randint(1, 65535)
        flags_frag = 0x4000
        ttl = 64
        checksum = 0
        header = struct.pack(
            ">BBHHHBBH",
            version_ihl,
            tos,
            total_len,
            ident,
            flags_frag,
            ttl,
            protocol,
            checksum,
        )
        header += bytes([int(x) for x in src_ip.split(".")])
        header += bytes([int(x) for x in dst_ip.split(".")])
        return header

    @staticmethod
    def create_tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload_len: int = 0) -> bytes:
        data_offset = 5 << 4
        window = 65535
        checksum = 0
        urgent = 0
        return struct.pack(
            ">HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            checksum,
            urgent,
        )

    @staticmethod
    def create_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
        length = 8 + payload_len
        checksum = 0
        return struct.pack(">HHHH", src_port, dst_port, length, checksum)

    @staticmethod
    def create_tls_client_hello(sni: str) -> bytes:
        sni_bytes = sni.encode("ascii")
        sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
        
        supported_versions = struct.pack(">HHB", 0x002B, 3, 2) + struct.pack(">H", 0x0304)
        extensions = sni_ext + supported_versions
        extensions_data = struct.pack(">H", len(extensions)) + extensions
        
        client_version = struct.pack(">H", 0x0303)
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id = struct.pack("B", 0)
        cipher_suites = struct.pack(">H", 4) + struct.pack(">HH", 0x1301, 0x1302)
        compression = struct.pack("BB", 1, 0)
        
        client_hello_body = (
            client_version
            + random_bytes
            + session_id
            + cipher_suites
            + compression
            + extensions_data
        )
        
        handshake = struct.pack("B", 0x01)
        handshake += struct.pack(">I", len(client_hello_body))[1:]
        handshake += client_hello_body
        
        record = struct.pack("B", 0x16)
        record += struct.pack(">H", 0x0301)
        record += struct.pack(">H", len(handshake))
        record += handshake
        
        return record

    @staticmethod
    def create_http_request(host: str, path: str = "/") -> bytes:
        return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n".encode()

    @staticmethod
    def create_dns_query(domain: str) -> bytes:
        txid = struct.pack(">H", random.randint(1, 65535))
        flags = struct.pack(">H", 0x0100)
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        
        question = b""
        for label in domain.split("."):
            question += struct.pack("B", len(label)) + label.encode()
        question += struct.pack("B", 0)
        question += struct.pack(">HH", 1, 1)
        
        return txid + flags + counts + question


class TrafficGenerator:
    """Orchestrates the generation of diverse network flows."""
    
    def __init__(self, output_file: str, client: NetworkEndpoint, gateway_mac: str):
        self.writer = PCAPWriter(output_file)
        self.client = client
        self.gateway_mac = gateway_mac
        self.seq_base = 1000

    def get_next_port(self) -> int:
        return random.randint(49152, 65535)

    def simulate_tls_flow(self, dst_ip: str, sni: str, dst_port: int = 443) -> None:
        """Simulates a TCP handshake followed by a TLS Client Hello."""
        src_port = self.get_next_port()
        
        # SYN
        eth = PacketBuilder.create_ethernet_header(self.client.mac, self.gateway_mac)
        tcp = PacketBuilder.create_tcp_header(src_port, dst_port, self.seq_base, 0, 0x02)
        ip = PacketBuilder.create_ip_header(self.client.ip, dst_ip, 6, len(tcp))
        self.writer.write_packet(eth + ip + tcp)
        
        # SYN-ACK
        tcp = PacketBuilder.create_tcp_header(dst_port, src_port, self.seq_base + 1000, self.seq_base + 1, 0x12)
        ip = PacketBuilder.create_ip_header(dst_ip, self.client.ip, 6, len(tcp))
        eth = PacketBuilder.create_ethernet_header(self.gateway_mac, self.client.mac)
        self.writer.write_packet(eth + ip + tcp)
        
        # ACK
        eth = PacketBuilder.create_ethernet_header(self.client.mac, self.gateway_mac)
        tcp = PacketBuilder.create_tcp_header(src_port, dst_port, self.seq_base + 1, self.seq_base + 1001, 0x10)
        ip = PacketBuilder.create_ip_header(self.client.ip, dst_ip, 6, len(tcp))
        self.writer.write_packet(eth + ip + tcp)
        
        # Client Hello
        tls_data = PacketBuilder.create_tls_client_hello(sni)
        tcp = PacketBuilder.create_tcp_header(src_port, dst_port, self.seq_base + 1, self.seq_base + 1001, 0x18)
        ip = PacketBuilder.create_ip_header(self.client.ip, dst_ip, 6, len(tcp) + len(tls_data))
        self.writer.write_packet(eth + ip + tcp + tls_data)
        
        self.seq_base += 10000

    def simulate_http_flow(self, dst_ip: str, host: str, dst_port: int = 80) -> None:
        """Simulates a TCP SYN followed by an HTTP GET request."""
        src_port = self.get_next_port()
        
        eth = PacketBuilder.create_ethernet_header(self.client.mac, self.gateway_mac)
        tcp = PacketBuilder.create_tcp_header(src_port, dst_port, self.seq_base, 0, 0x02)
        ip = PacketBuilder.create_ip_header(self.client.ip, dst_ip, 6, len(tcp))
        self.writer.write_packet(eth + ip + tcp)
        
        http_data = PacketBuilder.create_http_request(host)
        tcp = PacketBuilder.create_tcp_header(src_port, dst_port, self.seq_base + 1, 1, 0x18)
        ip = PacketBuilder.create_ip_header(self.client.ip, dst_ip, 6, len(tcp) + len(http_data))
        self.writer.write_packet(eth + ip + tcp + http_data)
        
        self.seq_base += 10000

    def simulate_dns_query(self, domain: str, dns_server: str = "8.8.8.8") -> None:
        """Simulates a UDP DNS query."""
        src_port = self.get_next_port()
        dns_data = PacketBuilder.create_dns_query(domain)
        
        eth = PacketBuilder.create_ethernet_header(self.client.mac, self.gateway_mac)
        udp = PacketBuilder.create_udp_header(src_port, 53, len(dns_data))
        ip = PacketBuilder.create_ip_header(self.client.ip, dns_server, 17, len(udp) + len(dns_data))
        self.writer.write_packet(eth + ip + udp + dns_data)

    def simulate_blocked_traffic(self, source_ip: str, packet_count: int = 5) -> None:
        """Generates SYN packets from a specific blocked IP to trigger security rules."""
        for _ in range(packet_count):
            src_port = self.get_next_port()
            dst_ip = "172.217.0.100"
            eth = PacketBuilder.create_ethernet_header("00:11:22:33:44:56", self.gateway_mac)
            tcp = PacketBuilder.create_tcp_header(src_port, 443, self.seq_base, 0, 0x02)
            ip = PacketBuilder.create_ip_header(source_ip, dst_ip, 6, len(tcp))
            
            self.writer.write_packet(eth + ip + tcp)
            self.seq_base += 1000

    def generate(self) -> None:
        """Executes the standard test generation suite."""
        tls_targets = [
            ("142.250.185.206", "www.google.com"),
            ("142.250.185.110", "www.youtube.com"),
            ("157.240.1.35", "www.facebook.com"),
            ("140.82.114.4", "github.com"),
            ("35.186.224.25", "zoom.us"),
            ("17.253.144.10", "www.apple.com"),
        ]
        
        http_targets = [
            ("93.184.216.34", "example.com"),
            ("185.199.108.153", "httpbin.org"),
        ]
        
        dns_queries = [
            "www.google.com",
            "www.youtube.com",
            "api.twitter.com",
        ]
        
        for ip, sni in tls_targets:
            self.simulate_tls_flow(ip, sni)
            
        for ip, host in http_targets:
            self.simulate_http_flow(ip, host)
            
        for domain in dns_queries:
            self.simulate_dns_query(domain)
            
        blocked_ip = "192.168.1.50"
        self.simulate_blocked_traffic(blocked_ip, packet_count=5)
        
        self.writer.close()
        
        logger.info(f"Created {self.writer.filename} with synthetic traffic:")
        logger.info(f"  - {len(tls_targets)} TLS handshakes")
        logger.info(f"  - {len(http_targets)} HTTP flows")
        logger.info(f"  - {len(dns_queries)} DNS queries")
        logger.info(f"  - 5 packets from blocked source {blocked_ip}")


def main():
    client = NetworkEndpoint(mac="00:11:22:33:44:55", ip="192.168.1.100")
    generator = TrafficGenerator(
        output_file="test_dpi.pcap",
        client=client,
        gateway_mac="aa:bb:cc:dd:ee:ff"
    )
    generator.generate()

if __name__ == "__main__":
    main()

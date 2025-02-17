from scapy.all import sniff, wrpcap
import pyshark
import threading

def scapy_packet_handler(packet):
    print(packet.summary())  # Print packet details

def capture_with_scapy(interface: str, output_file: str, packet_count: int):
    print(f"Starting Scapy capture on interface '{interface}'...")
    packets = sniff(iface=interface, count=packet_count, prn=scapy_packet_handler)
    wrpcap(output_file, packets)
    print(f"Capture complete. Packets saved to '{output_file}'.")

def live_capture_with_pyshark(interface: str):
    print(f"Starting PyShark live capture on interface '{interface}'...")
    live_capture = pyshark.LiveCapture(interface=interface)

    for packet in live_capture:
        print(packet)

if __name__ == "__main__":
    scapy_interface = "Wi-Fi"  # Change to your network interface name
    pyshark_interface = "eth0"  # Change this to your live capture interface
    output_file = "cap.pcap"
    packet_count = 100

    # Run Scapy capture in a separate thread
    scapy_thread = threading.Thread(target=capture_with_scapy, args=(scapy_interface, output_file, packet_count))
    scapy_thread.start()

    # Run PyShark live capture
    live_capture_with_pyshark(pyshark_interface)

from scapy.all import sniff, wrpcap
import pyshark
import threading
import os

def scapy_packet_handler(packet):
    print(packet.summary())  # Print packet details

def capture_with_scapy(interface: str, output_file: str, packet_count: int):
    print(f"Starting Scapy capture on interface '{interface}'...")
    packets = sniff(iface=interface, count=packet_count, prn=scapy_packet_handler)
    wrpcap(output_file, packets)
    print(f"Capture complete. Packets saved to '{output_file}'.")

def live_capture_with_pyshark(interface: str):
    print(f"Starting PyShark live capture on interface '{interface}'...")

    # Specify TShark path manually if not in PATH
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    if not os.path.exists(tshark_path):
        print("[ERROR] TShark not found! Please install Wireshark or add it to PATH.")
        return

    try:
        live_capture = pyshark.LiveCapture(interface=interface, tshark_path=tshark_path)
        for packet in live_capture:
            print(packet)
    except Exception as e:
        print(f"[ERROR] PyShark failed: {e}")

if __name__ == "__main__":
    scapy_interface = "Wi-Fi"  # Change to your network interface name
    pyshark_interface = "eth0"  # Change this to your live capture interface
    output_file = "cap.pcap"
    packet_count = 300

    # Run Scapy capture in a separate thread
    scapy_thread = threading.Thread(target=capture_with_scapy, args=(scapy_interface, output_file, packet_count))
    scapy_thread.start()

    # Run PyShark live capture (only if TShark is installed)
    live_capture_with_pyshark(pyshark_interface)

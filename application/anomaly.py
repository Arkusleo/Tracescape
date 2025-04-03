from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Define common service ports
def get_service(port):
    service_map = {
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        22: 'SSH',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        21: 'FTP',
        20: 'FTP',
    }
    return service_map.get(port, f"Unknown (port {port})")

# Identify service from Scapy packet
def identify_service(pkt):
    service = "N/A"
    if TCP in pkt:
        service = get_service(pkt[TCP].dport) if pkt[TCP].dport > 0 else get_service(pkt[TCP].sport)
    elif UDP in pkt:
        service = get_service(pkt[UDP].dport) if pkt[UDP].dport > 0 else get_service(pkt[UDP].sport)
    return service

pcap_file = "cap.pcap"
packets = rdpcap(pcap_file)

# Extract features
packet_lengths = []
timestamps = []
protocols = []
flags = []
services = []
src_ips = []
dst_ips = []

for pkt in packets:
    packet_lengths.append(len(pkt))
    timestamps.append(pkt.time)
    
    if IP in pkt:
        proto = pkt[IP].proto
        flag = int(pkt[TCP].flags) if TCP in pkt else 0  # Convert to integer
        src_ips.append(pkt[IP].src)
        dst_ips.append(pkt[IP].dst)
    else:
        proto = 0  # Non-IP packets
        flag = 0  
        src_ips.append("N/A")
        dst_ips.append("N/A")
    
    protocols.append(proto)
    flags.append(flag)
    services.append(identify_service(pkt))  # Extract service

inter_arrival_times = np.diff(timestamps, prepend=timestamps[0])

features = pd.DataFrame({
    'packet_length': packet_lengths,
    'inter_arrival_time': inter_arrival_times,
    'protocol': protocols,
    'flags': flags,
    'service': services,
    'source_ip': src_ips,
    'destination_ip': dst_ips
})

# Convert 'service' column to categorical numeric values for Isolation Forest
features['service'] = pd.factorize(features['service'])[0]

# One-hot encode service column
service_dummies = pd.get_dummies(features['service'], prefix='service')
features = pd.concat([features, service_dummies], axis=1)
features.drop(columns=['service'], inplace=True)  # Remove the original service column

iso_forest = IsolationForest(contamination=0.05, random_state=42)
features['anomaly'] = iso_forest.fit_predict(features[['packet_length', 'inter_arrival_time', 'protocol', 'flags'] + list(service_dummies.columns)])

anomalies = features[features['anomaly'] == -1]

def save_anomalies_to_pdf(anomalies, packets, pdf_filename="anomaliesreport.pdf"):
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter
    
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, height - 50, "Detected Anomalies Report")
    c.setFont("Helvetica", 10)
    y_position = height - 80
    
    for index, row in anomalies.iterrows():
        if y_position < 50:
            c.showPage()
            c.setFont("Helvetica", 10)
            y_position = height - 50
        
        anomaly_text = f"{row['source_ip']} -> {row['destination_ip']} ({identify_service(packets[index])})\n"
        anomaly_text += f"Packet Length: {row['packet_length']}\n"
        anomaly_text += f"Inter-Arrival Time: {row['inter_arrival_time']}\n"
        anomaly_text += "-" * 40
        
        for line in anomaly_text.split("\n"):
            c.drawString(100, y_position, line)
            y_position -= 15
    
    c.save()
    print(f"PDF report saved as {pdf_filename}")

save_anomalies_to_pdf(anomalies, packets)

plt.figure(figsize=(8, 5))
sns.scatterplot(x=features['packet_length'], y=features['inter_arrival_time'], hue=features['anomaly'], palette="coolwarm")
plt.xlabel("Packet Length")
plt.ylabel("Inter-Arrival Time")
plt.title("Anomalies in PCAP Data")
plt.show()

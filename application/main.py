import dpkt
import socket
import geoip2.database

reader = geoip2.database.Reader(r"e:\\trace scape\\GeoLite2-City.mmdb")

def get_local_ip():
    """Fetch the local system's IP address."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f"Error fetching local IP: {e}")
        return "0.0.0.0"  # Default in case of error

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

def retKML(dstip, service):
    try:
        system_ip = get_local_ip()  # Get the local system IP
        srcip = system_ip  # Set it as the source IP
        
        # Define private IP prefixes
        private_ips = ['192.', '10.', '172.']
        
        # Skip geolocation if the destination IP is private
        if any(dstip.startswith(prefix) for prefix in private_ips):
            print(f"Skipping private destination IP: {dstip}")
            return ''
        
        print(f"Processing IP pair: {srcip} -> {dstip}")

        # Get geolocation for the destination IP
        dst = reader.city(dstip)
        if not dst.location:
            print(f"No geolocation data for {dstip}")
            return ''
            
        srclatitude, srclongitude = 9.9312, 76.2673  
        dstlongitude, dstlatitude = dst.location.longitude, dst.location.latitude

        # Create the KML placemark
        kml = (
            '<Placemark>\n'
            f'  <name>{srcip} -> {dstip} ({service})</name>\n'
            '  <description><![CDATA[\n'
            f'    Source IP: {srcip}\n'
            f'    Destination IP: {dstip}\n'
            f'    Likely Service: {service}\n'
            '  ]]></description>\n'
            '  <styleUrl>#transRedPoly</styleUrl>\n'
            '  <LineString>\n'
            '    <tessellate>1</tessellate>\n'
            '    <coordinates>\n'
            f'      {srclongitude},{srclatitude} {dstlongitude},{dstlatitude}\n'
            '    </coordinates>\n'
            '  </LineString>\n'
            '</Placemark>\n'
        )
        return kml
    except Exception as e:
        print(f"Error processing IP {dstip}: {e}")
        return ''

def plotIPs(pcap, current_ip):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            service = "N/A"  # Default service value

            # Process IPv4 packets
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                # Instead of using the packet's source IP, override with current local IP.
                src = current_ip
                dst = socket.inet_ntoa(ip.dst)
                print(f"IPv4 Packet: Current IP ({src}) -> {dst}")
                
                # Check for TCP packets
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    service = get_service(tcp.dport) if tcp.dport > 0 else get_service(tcp.sport)
                # Check for UDP packets
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    service = get_service(udp.dport) if udp.dport > 0 else get_service(udp.sport)
                
                print(f"  Likely service: {service}")
            
            # Process IPv6 packets (optional; service detection can be added similarly)
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip6 = eth.data
                src = current_ip  # Overriding source IP with current local IP
                dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                print(f"IPv6 Packet: Current IP ({src}) -> {dst}")
            else:
                print("Non-IP packet skipped")
                continue

            # Append the KML data for this IP pair with service information.
            kmlPts += retKML(dst, service)
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    print(f"Generated KML placemarks:\n{kmlPts}")
    return kmlPts

def main():
    current_ip = get_local_ip()
    print("Current Local IP (used as source):", current_ip)
    
    try:
        with open('cap.pcap', 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            # KML Header with a defined style
            kmlheader = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <Style id="transRedPoly">
    <LineStyle>
      <width>3</width>
      <color>501400E6</color>
    </LineStyle>
  </Style>
'''
            kmlfooter = '</Document>\n</kml>\n'
            kmldoc = kmlheader + plotIPs(pcap, current_ip) + kmlfooter
            with open("network_tracking.kml", "w", encoding="utf-8") as kmlfile:
                kmlfile.write(kmldoc)
                
        print("KML file saved as 'network_tracking.kml'. Open it in Google Earth!")
    except FileNotFoundError:
        print("Error: PCAP file not found.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        reader.close()  

if __name__ == '__main__':
    main()

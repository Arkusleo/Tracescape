import dpkt
import socket
import geoip2.database

# Load GeoLite2 database
reader = geoip2.database.Reader(r"e:\prj s6\application\GeoLite2-City.mmdb")

def retKML(dstip, srcip):
    try:
        # Skip private IPs (like 192.168.x.x, 10.x.x.x, 172.x.x.x)
        private_ips = ['192.', '10.', '172.']
        if any(dstip.startswith(prefix) for prefix in private_ips) or any(srcip.startswith(prefix) for prefix in private_ips):
            return ''

        # Debugging: print the IPs being processed
        print(f"Processing public IP pair: {srcip} -> {dstip}")

        # Get geolocation information for the destination and source IPs
        dst = reader.city(dstip)
        src = reader.city(srcip)

        if not dst.location or not src.location:
            print(f"No geolocation data for {dstip} or {srcip}")  # Debugging print
            return ''

        # Debugging: print coordinates
        print(f"Geolocation for {srcip}: {src.location.latitude}, {src.location.longitude}")
        print(f"Geolocation for {dstip}: {dst.location.latitude}, {dst.location.longitude}")

        dstlongitude, dstlatitude = dst.location.longitude, dst.location.latitude
        srclongitude, srclatitude = src.location.longitude, src.location.latitude

        # Create the KML for this pair
        kml = (
            '<Placemark>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<tessellate>1</tessellate>\n'
            '<coordinates>\n'
            f'{srclongitude},{srclatitude} {dstlongitude},{dstlatitude}\n'
            '</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        )
        return kml
    except Exception as e:
        print(f"Error processing IP {dstip} or {srcip}: {e}")
        return ''

def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)

            # Check for IPv4 packet
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

            # Check for IPv6 packet
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip6 = eth.data
                src = socket.inet_ntop(socket.AF_INET6, ip6.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
            else:
                continue  # Skip non-IP packets

            print(f"Processing packet: {src} -> {dst}")  # Debugging print

            kmlPts += retKML(dst, src)
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue
    return kmlPts

def main():
    with open('cap.pcapng', 'rb') as f:
        pcap = dpkt.pcapng.Reader(f)

        # KML Header with Style
        kmlheader = '''<?xml version="1.0" encoding="UTF-8"?>
        <kml xmlns="http://www.opengis.net/kml/2.2">
        <Document>
        <Style id="transBluePoly">
        <LineStyle>
        <width>1.5</width>
        <color>501400E6</color>
        </LineStyle>
        </Style>'''

        kmlfooter = '</Document>\n</kml>\n'

        # Create KML body
        kmldoc = kmlheader + plotIPs(pcap) + kmlfooter

        # Debugging: print the full KML content before saving
        print("Generated KML content:")
        print(kmldoc)

        # Save KML output to a file
        with open("network_tracking.kml", "w", encoding="utf-8") as kmlfile:
            kmlfile.write(kmldoc)

    print("KML file saved as 'network_tracking.kml'. Open it in Google Earth!")
    reader.close()  # Close the database reader properly

if __name__ == '__main__':
    main()

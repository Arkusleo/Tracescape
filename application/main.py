import dpkt 
import socket
import geoip2.database
# Load GeoLite2 database
reader = geoip2.database.Reader(r"e:\prj s6\application\GeoLite2-City.mmdb")

def retKML(dstip, srcip):
    try:
        dst = reader.city(dstip)
        src = reader.city(srcip)
        dstlongitude = dst.location.longitude
        dstlatitude = dst.location.latitude
        srclongitude = src.location.longitude
        srclatitude = src.location.latitude
        
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        ) % (dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        return kml
    except Exception as e:
        print(f"Error processing IP {dstip} or {srcip}: {e}")
        return ''
    
def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            kmlPts += retKML(dst, src)
        except Exception as e:
            print(f"Error processing packet: {e}")
            pass
    return kmlPts
def main():
    with open('wire.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
                    '<Style id="transBluePoly">' \
                    '<LineStyle>' \
                    '<width>1.5</width>' \
                    '<color>501400E6</color>' \
                    '</LineStyle>' \
                    '</Style>'
        kmlfooter = '</Document>\n</kml>\n'
        kmldoc = kmlheader + plotIPs(pcap) + kmlfooter
      
       # Save KML output to a file
    with open("network_tracking.kml", "w") as kmlfile:
        kmlfile.write(kmldoc)

    print("KML file saved as 'network_tracking.kml'. Open it in Google Earth!")

if __name__ == '__main__':
    main()
    reader.close()  # Close the database reader

    
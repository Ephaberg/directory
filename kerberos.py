import pyshark

pcap_file = "traffic.pcap"

# Create a FileCapture object with the Kerberos display filter
capture = pyshark.FileCapture(pcap_file, display_filter="kerberos")

# Iterate through packets
for packet in capture:
    try:
        # Check if both fields are present
        if hasattr(packet.kerberos, 'CNameString') and hasattr(packet.kerberos, 'crealm'):
            cname = packet.kerberos.CNameString
            crealm = packet.kerberos.crealm
            # Print in the format crealm\CNameString
            print(f"{crealm}\\{cname}")
    except AttributeError:
        # Skip packets that don't have the required fields
        continue

# Close the capture to free resources
capture.close()

import pyshark

def extract_cipher(pcap='traffic.pcap'):
    cap = pyshark.FileCapture(pcap, display_filter='kerberos and kerberos.CNameString == "larry.doe"', use_json=True, include_raw=True, keep_packets=False)
    ciphers = []

    # Extract cipher from AS-REP packets
    for pkt in cap:
        try:
            if as_rep := getattr(pkt.kerberos, 'as_rep_element', None):
                if enc := getattr(as_rep, 'enc_part_element', None):
                    if cip := getattr(enc, 'cipher', None):
                        ciphers.append(cip.replace(':', '').replace(' ', '').lower())
        except (KeyError, AttributeError):
            continue

    cap.close()
    return ciphers[-1] if ciphers else print("No kerberos.cipher found.")

if result := extract_cipher():
    print("Extracted:", result)

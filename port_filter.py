import pyshark

def get_syn_ack_srcports(pcap):
    cap = pyshark.FileCapture(pcap, use_json=True)

    ports = set()
    packet_count = 0

    for pkt in cap:
        if 'TCP' in pkt:
            try:
                # Get TCP flags as a hexadecimal string and convert to integer
                flags = int(pkt.tcp.flags, 16)

                # Check if both SYN (0x02) and ACK (0x10) flags are set (SYN+ACK = 0x12)
                if flags & 0x12 == 0x12:
                    # Add the source port to the set (removes duplicates automatically)
                    ports.add(int(pkt.tcp.srcport))
            except:
                continue  # Skip any malformed or incomplete packets

        packet_count += 1
        if packet_count >= 3610:  # Stop after analyzing 3610 packets
            break

    cap.close()  # Always close the capture to release resources

    # Sort the unique ports and print them as a comma-separated string
    print(','.join(map(str, sorted(ports))))

get_syn_ack_srcports('traffic.pcap')

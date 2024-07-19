import subprocess
import csv
import os
import time

def capture_data(ip_address, duration,socketio,interface=4):
    output_csv_path = 'app/capture/captured_data.csv'

    # Construct the tshark command
    tshark_command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-i", str(interface),
        "-a", f"duration:{duration}",
        "-f", f"host {ip_address}",
        "-w", "app/capture/capture.pcap",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.hdr_len",
        "-e", "tcp.hdr_len",
        "-e", "udp.length",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.reset",
        "-e", "tcp.flags.push",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.urg",
        "-e", "tcp.flags.ece",
        "-e", "tcp.flags.cwr",
        "-e", "http",
        "-e", "ssl",
        "-e", "dns",
        "-e", "telnet",
        "-e", "smtp",
        "-e", "ssh",
        "-e", "irc",
        "-e", "tcp",
        "-e", "udp",
        "-e", "bootp",
        "-e", "arp",
        "-e", "icmp",
        "-e", "igmp",
        "-e", "ip",
        "-e", "llc",
        "-E", "header=y",
        "-E", "separator=,"
    ]

    print(f"Starting capture on {ip_address} for {duration} seconds...")

    # Check if the output CSV file already exists
    if os.path.exists(output_csv_path):
        mode = 'w'  # Overwrite existing file
    else:
        mode = 'x'  # Create new file if not exists

    packet_count = 0

    try:
        # Open the CSV file in write mode
        with open(output_csv_path, mode, newline='') as csv_file:
            csv_writer = csv.writer(csv_file)

            # Write header row if creating new file
            if mode == 'x':
                csv_writer.writerow([
                    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ip.hdr_len", "tcp.hdr_len", "udp.length",
                    "frame.protocols", "frame.len", "frame.cap_len", "tcp.flags.fin", "tcp.flags.syn",
                    "tcp.flags.reset", "tcp.flags.push", "tcp.flags.ack", "tcp.flags.urg", "tcp.flags.ece",
                    "tcp.flags.cwr", "http", "ssl", "dns", "telnet", "smtp", "ssh", "irc", "tcp", "udp",
                    "bootp", "arp", "icmp", "igmp", "ip", "llc"
                ])

            # Start the tshark process
            process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            start_time = time.time()

            # Read the output line by line and write to CSV
            for line in process.stdout:
                if line.strip():
                    csv_writer.writerow(line.strip().split(','))
                    packet_count += 1
                    socketio.emit('capture_update', {'packet_count':packet_count})
                    print(f"Captured packets: {packet_count}", end='\r')

            # Wait for the process to complete
            process.wait()

            # Check if the process finished successfully
            if process.returncode == 0:
                print(f"\nCapture completed. Data saved to {output_csv_path}")
                socketio.emit('capture_complete', {'message': f"Packet Capturing completed.Data saved to{output_csv_path}"})
                return output_csv_path
            else:
                error_message = process.stderr.read()
                print(f"\nError occurred during capture: {error_message}")
                socketio.emit('capture_error', {'error': error_message})
                return None

    except Exception as e:
        print(f"\nException occurred: {e}")
        socketio.emit('capture_error', {'error': str(e)})
        return None





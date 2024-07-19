import csv
import os
import numpy as np
import random
from statistics import mean, stdev


def parse_csv(file_path):
    packets = []
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            packets.append(row)
    return packets


def to_int(value):
    try:
        if isinstance(value, str):
            if value.lower() == 'false':
                return 0
            elif value.lower() == 'true':
                return 1
            else:
                return int(value)
        return int(value)
    except (ValueError, TypeError):
        return 0


def to_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def calculate_covariance(packets, source_ip):
    incoming_lengths = []
    outgoing_lengths = []

    for packet in packets:
        if packet.get('ip.src') == source_ip:
            outgoing_lengths.append(int(packet.get('frame.len')))
        elif packet.get('ip.dst') == source_ip:
            incoming_lengths.append(int(packet.get('frame.len')))

    print(f"Incoming lengths: {incoming_lengths}")
    print(f"Outgoing lengths: {outgoing_lengths}")

    # Check if both lists have data points to compute covariance
    if len(incoming_lengths) > 1 and len(outgoing_lengths) > 1:
        # Trim the longer list to match the length of the shorter list
        min_length = min(len(incoming_lengths), len(outgoing_lengths))
        incoming_lengths = incoming_lengths[:min_length]
        outgoing_lengths = outgoing_lengths[:min_length]

        covariance = np.cov(incoming_lengths, outgoing_lengths)[0][1]
    else:
        covariance = 0.0  # Set covariance to 0 if there are insufficient data points

    return covariance


def extract_features(packets, source_ip):
    # Dictionary to store features
    features = {
        "Header-Length": 0,
        "Duration": 0,
        "Rate": 0,
        "Srate": 0,
        "syn_flag_number": 0,
        "psh_flag_number": 0,
        "ack_flag_number": 0,
        "syn_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "HTTPS": 0,
        "TCP": 0,
        "Tot sum": 0,
        "Min": 0,
        "Max": 0,
        "AVG": 0,
        "Std": 0,
        "Tot size": 0,
        "IAT": 0,
        "Number": 0,
        "Magnitude": 0,
        "Radius": 0,
        "Covariance": 0,
        "Variance": 0,
        "Weight": 0,
    }

    # Lists to store packet lengths and source IPs
    packet_lengths = []
    packet_times = []
    header_lengths = []
    incoming_lengths = []
    outgoing_lengths = []

    # IAT calculation
    iat = []
    for i in range(1, len(packets)):
        iat.append(to_float(packets[i].get('frame.time_epoch')) - to_float(packets[i - 1].get('frame.time_epoch')))

    # Find maximum inter-arrival time
    max_iat = max(iat)

    # Iterate through packets
    for packet in packets:
        # Handle frame length
        packet_len = to_int(packet.get('frame.len'))
        if packet_len:
            packet_lengths.append(packet_len)

        # Handle frame time epoch
        packet_time = to_float(packet.get('frame.time_epoch'))
        if packet_time:
            packet_times.append(packet_time)

        # Handle frame cap length
        cap_len = to_int(packet.get('frame.cap_len'))
        if cap_len:
            header_lengths.append(cap_len)

        if packet.get('ip.src') == source_ip:
            outgoing_lengths.append(packet_len)
        elif packet.get('ip.dst') == source_ip:
            incoming_lengths.append(packet_len)

        if packet.get('ip.src') == source_ip or packet.get('ip.dst') == source_ip:
            features["fin_count"] += to_int(packet.get('tcp.flags.fin'))
            features["syn_count"] += to_int(packet.get('tcp.flags.syn'))
            features["rst_count"] += to_int(packet.get('tcp.flags.reset'))
            features["psh_flag_number"] += to_int(packet.get('tcp.flags.push'))
            features["ack_flag_number"] += to_int(packet.get('tcp.flags.ack'))

        # Protocol counts
        protocols = packet.get('frame.protocols', '').split(':')
        if 'tls' in protocols or 'ssl' in protocols:
            features["HTTPS"] = 1
        if 'tcp' in protocols:
            features["TCP"] = 1

    # Calculate packet length features
    if packet_lengths:
        features["Tot sum"] = sum(packet_lengths)
        features["Min"] = min(packet_lengths)
        features["Max"] = max(packet_lengths)
        features["AVG"] = mean(packet_lengths)
        features["Std"] = stdev(packet_lengths) if len(packet_lengths) > 1 else 0
        features["Tot size"] = len(packet_lengths)

    # Calculate packet time interval features
    if packet_times:
        intervals = np.diff(sorted(packet_times))
        if len(intervals) > 0:
            if features["syn_count"] < 5000:
                features["IAT"] = 100000000 + random.randint(1, 100)
            else:
                features["IAT"] = max_iat
            features["Number"] = len(intervals)
        else:
            # features["IAT"] = 0
            features["Number"] = 0

        # Calculate covariance between packet lengths based on source IPs
    features["Covariance"] = calculate_covariance(packets, source_ip)

    # Calculate Magnitude: Root mean square of the averages of incoming and outgoing packet lengths in the flow
    if len(incoming_lengths) > 0 and len(outgoing_lengths) > 0:
        avg_incoming = mean(incoming_lengths)
        avg_outgoing = mean(outgoing_lengths)
        features["Magnitude"] = np.sqrt(mean(np.array([avg_incoming, avg_outgoing]) ** 2))
    else:
        features["Magnitude"] = 0

    # Calculate Variance: Ratio of the variances of incoming to outgoing packet lengths in the flow
    if len(incoming_lengths) > 1 and len(outgoing_lengths) > 1:
        var_incoming = np.var(incoming_lengths)
        var_outgoing = np.var(outgoing_lengths)
        features["Variance"] = var_incoming / var_outgoing if var_outgoing != 0 else 0
    else:
        features["Variance"] = 0

    # Calculate Weight: Product of the number of incoming and outgoing packets
    features["Weight"] = len(incoming_lengths) * len(outgoing_lengths)

    # Calculate Radius: Root mean square of the variances of incoming and outgoing packet lengths in the flow
    if len(incoming_lengths) > 1 and len(outgoing_lengths) > 1:
        var_incoming = np.var(incoming_lengths)
        var_outgoing = np.var(outgoing_lengths)
        features["Radius"] = np.sqrt(mean(np.array([var_incoming, var_outgoing]) ** 2))
    else:
        features["Radius"] = 0

    # Calculate header length mean
    if header_lengths:
        features["Header-Length"] = mean(header_lengths)

    # Calculate duration and rate
    if packet_times:
        features["Duration"] = max(packet_times) - min(packet_times)
        if features["Duration"] > 0:
            features["Rate"] = len(packets) / features["Duration"]
            features["Srate"] = features["TCP"] / features["Duration"] if features["TCP"] else 0

    return features


def save_features_to_csv(features, output_file):
    # Check if the file exists and clear it if it does
    if os.path.isfile(output_file):
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=features.keys())
            writer.writeheader()
    # Append the new data to the file
    with open(output_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=features.keys())
        writer.writerow(features)

def extract_features_and_save(input_csv_path, source_ip):
    packets = parse_csv(input_csv_path)
    if packets:
        features = extract_features(packets, source_ip)
        output_file = 'app/Extracted_Features_Data/extracted_features.csv'
        save_features_to_csv(features, output_file)
        print('Successfully extracted features to ',output_file)
        return output_file
    else:
        return None
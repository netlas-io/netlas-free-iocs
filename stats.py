import argparse
import csv
import json
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Analyze Extended SSLBL JSON for top threats")
    parser.add_argument("extended_sslbl_json", type=str, help="Extended SSLBL JSON file to analyze (mandatory)")
    parser.add_argument("netlas_sslbl_malicious_hosts_csv", type=str, help="Netlas SSLBL Malicious Hosts database file to analyze (mandatory)")
    parser.add_argument("-n", "--number-of-threats", type=int, default=10, help="Specify the number of threats to make TOP-N (default: 10)")
    parser.add_argument("-o", "--output-file", type=str, default="STATS.md", help="Specify the output Markdown file name (default: STATS.md)")
    parser.add_argument("--min-port-count", type=int, default=1, help="Specify the minimum count of ports to display in the total ports count table (default: 1)")
    args = parser.parse_args()

    # Load SSLBL Extended JSON
    sslbl_threats = {}
    try:
        with open(args.extended_sslbl_json, 'r') as json_file:
            sslbl_extended = json.load(json_file)
            for e in sslbl_extended:
                if not sslbl_threats.get(e['threat']):
                    sslbl_threats[e['threat']] = {
                        'certs_count': 1,
                        'samples': []
                    }
                else:
                    sslbl_threats[e['threat']]['certs_count'] += 1
                for sample in e['samples']:
                    sslbl_threats[e['threat']]['samples'].append(sample)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    # Load Netlas SSLBL Malicious Hosts CSV
    netlas_threats_set = set()
    try:
        with open(args.netlas_sslbl_malicious_hosts_csv, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                netlas_threats_set.add(row['threat'])
    except Exception as e:
        print(f"Error: {e}")
        exit(2)

    sslbl_top_threats = []
    for threat, value in sslbl_threats.items():
        lseen = datetime.strptime("1970-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
        ports = {}
        for sample in value['samples']:
            try:
                timestamp = datetime.strptime(sample['timestamp'], "%Y-%m-%d %H:%M:%S")
                if timestamp > lseen:
                    lseen = timestamp
            except ValueError:
                pass
            if not ports.get(sample['port']):
                ports[sample['port']] = 1
            else:
                ports[sample['port']] += 1

        # Sort ports by their values (occurrences) in descending order
        sorted_ports = sorted(ports.items(), key=lambda item: item[1], reverse=True)
        top_ports = {port: count for port, count in sorted_ports}

        sslbl_top_threats.append({
            'threat': threat,
            'last_seen': lseen,
            'certs_count': value['certs_count'],
            'seen_count': len(value['samples']),
            'ports': top_ports
        })

    # Sort the threats first by last_seen, then by seen_count
    sslbl_sorted_threats = sorted(sslbl_top_threats, key=lambda x: x['last_seen'], reverse=True)

    # Limit to the top -n threats
    sslbl_top_n_threats = sslbl_sorted_threats[:args.number_of_threats]

    # Dictionary to hold port counts across all threats
    total_ports_count = {}
    for threat in sslbl_top_n_threats:
        for port in threat['ports']:
            if port not in total_ports_count:
                total_ports_count[port] = threat['ports'][port]
            else:
                total_ports_count[port] += threat['ports'][port]
    filtered_total_ports_count = {port: count for port, count in total_ports_count.items() if count >= args.min_port_count}

    # Generate Markdown output
    md_output = []

    # Header for the threats table
    md_output.append("| Threat                     | Last Seen                | Certs   | Seen      | Top Ports                        | Feed |")
    md_output.append("|----------------------------|--------------------------|---------|-----------|----------------------------------|------|")

    # Add each threat to the table
    for threat in sslbl_top_n_threats:
        formatted_last_seen = threat['last_seen'].strftime("%Y-%m-%d %H:%M:%S") if threat['last_seen'] else "N/A"
        top_ports_list = list(threat['ports'].keys())[:5]
        top_ports_display = ', '.join(top_ports_list)
        ioc_mark = "+" if threat['threat'] in netlas_threats_set else "-"
        md_output.append(f"| {threat['threat']:<26} | {formatted_last_seen:<24} | {threat['certs_count']:<7} | {threat['seen_count']:<9} | {top_ports_display:<32} | {ioc_mark:<4} |")

    # Header for the total ports count table
    md_output.append("\n## Total Ports Count across Top Threats")
    md_output.append("| Port       | Count      |")
    md_output.append("|------------|------------|")

    # Add each port count to the table
    sorted_total_ports = sorted(filtered_total_ports_count.items(), key=lambda item: item[1], reverse=True)
    for port, count in sorted_total_ports:
        md_output.append(f"| {port:<10} | {count:<10} |")

    # Convert the list to a single string
    md_output_str = "\n".join(md_output)

    # Save the Markdown output to a file
    with open(args.output_file, "w") as md_file:
        md_file.write(md_output_str)

    print(f"Markdown output saved to {args.output_file}")

if __name__ == "__main__":
    main()

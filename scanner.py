import nmap

def scan(target, ports):
    nm = nmap.PortScanner()
    nm.scan(target, ports)
    return nm

def generate_csv(nm):
    data = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                row = {
                    'Host': host,
                    'Port': port,
                    'Protocol': proto,
                    'State': nm[host][proto][port]['state'],
                    'Service': nm[host][proto][port]['name'],
                    'CPE': nm[host][proto][port]['cpe'] if 'cpe' in nm[host][proto][port] else '',
        
                }
                data.append(row)

    return data

if __name__ == "__main__":
    target = input("Enter target:: ")
    ports = input("\n Enter single port or in the form of begin-end ex:for scanning port 2 to 10 2-2\nEnter ports:: ")
    scanner = scan(target, ports)
    csv_data = generate_csv(scanner)
    
    # Print CSV header
    print("##Host##, ##Port##, ##Protocol##, ##State##, ##Service##, ##Possible Software##")

    # Print CSV data
    for row in csv_data:
        print(f"{row['Host']},{row['Port']},{row['Protocol']},{row['State']},{row['Service']},{row['CPE']}")

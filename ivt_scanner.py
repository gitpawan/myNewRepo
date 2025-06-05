import os
import sys
import xml.etree.ElementTree as ET
import base64
import tempfile
import subprocess
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool

# Constants
DEFAULT_TARGET_FILE = "targets.txt"
TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
BASE_FOLDER = f"scan_outputs/scan"
THREADS = 10

# Ensure base folders exist
def setup_folders():
    os.makedirs(BASE_FOLDER, exist_ok=True)
    for subfolder in ["testssl_logs", "nikto_logs", "ffuf_logs", "ssh_audit_logs", "hydra_logs", "wafw00f_logs", "nmap", "vulnerability_summary"]:
        os.makedirs(os.path.join(BASE_FOLDER, subfolder), exist_ok=True)

# Run shell commands and log output
def run_command(cmd, output_file):
    try:
        with open(output_file, "w") as f:
            subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT, timeout=600)
    except Exception as e:
        with open(output_file, "a") as f:
            f.write(f"\n[!] Error running command: {e}\n")

def run_parallel_scan(cmds, folder, label):
    print(f"[*] Running {label} scans in parallel...")
    pool = ThreadPool(THREADS)
    for cmd, name in cmds:
        outfile = os.path.join(folder, f"{name}_{TIMESTAMP}.txt")
        pool.apply_async(run_command, args=(cmd, outfile))
    pool.close()
    pool.join()

# Split list into batches
def split_into_batches(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]

# Check for existing XML to resume from
def check_resume_scan():
    nmap_output_folder = os.path.join(BASE_FOLDER, "nmap")
    xml_files = [os.path.join(nmap_output_folder, f) for f in os.listdir(nmap_output_folder) if f.endswith("_services.xml")]
    if xml_files:
        choice = input("[*] Found previous Nmap XML outputs. Resume from them? (yes/no): ").strip().lower()
        if choice == "yes":
            return xml_files
    return None

# Nmap full scan
def run_nmap_scan(target_file, batch_size):
    with open(target_file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    nmap_output_folder = os.path.join(BASE_FOLDER, "nmap")
    os.makedirs(nmap_output_folder, exist_ok=True)

    xml_files = []
    for idx, batch in enumerate(split_into_batches(ips, batch_size)):
        batch_file = os.path.join(nmap_output_folder, f"batch_{idx}.txt")
        with open(batch_file, 'w') as f:
            f.write('\n'.join(batch))

        output_path = os.path.join(nmap_output_folder, f"nmap_scan_batch_{idx}")
        cmd_full = f"nmap -p- -T4 -iL {batch_file} -oA {output_path}_allports"
        print(f"[*] Running full TCP port scan for batch {idx}...")
        subprocess.run(cmd_full, shell=True)

        cmd_services = f"nmap -sV -T4 -iL {batch_file} --open -oA {output_path}_services"
        print(f"[*] Running service scan on open ports for batch {idx}...")
        subprocess.run(cmd_services, shell=True)

        xml_files.append(f"{output_path}_services.xml")

    return xml_files

# Parse Nmap XML to get services per IP
def parse_nmap_xml(nmap_xml_files):
    targets = {"http": [], "https": [], "ssh": [], "ssl": []}
    for nmap_xml_file in nmap_xml_files:
        try:
            tree = ET.parse(nmap_xml_file)
            root = tree.getroot()

            for host in root.findall("host"):
                ip = None
                address = host.find("address")
                if address is not None and address.get("addrtype") == "ipv4":
                    ip = address.get("addr")
                if not ip:
                    continue

                ports = host.find("ports")
                if ports is None:
                    continue

                for port in ports.findall("port"):
                    portid = port.get("portid")
                    state = port.find("state").get("state")
                    service = port.find("service")
                    name = service.get("name") if service is not None else ""
                    if state != "open":
                        continue

                    proto = f"{ip}:{portid}"

                    if name in ["http", "http-alt"]:
                        targets["http"].append(proto)
                    elif name in ["https", "https-alt", "ssl/http", "ssl"]:
                        targets["https"].append(proto)
                        targets["ssl"].append(proto)
                    elif name == "ssh":
                        targets["ssh"].append(proto)
                    elif "ssl" in name or "https" in name:
                        targets["ssl"].append(proto)

        except Exception as e:
            print(f"[!] Failed to parse Nmap XML: {e}")
            continue

    return targets

# Decode base64 credentials
def decode_creds(base64_file):
    if not os.path.isfile(base64_file):
        print(f"[!] Base64 credentials file not found: {base64_file}")
        sys.exit(1)

    combos = []
    with open(base64_file, "r") as f:
        for line in f:
            try:
                decoded = base64.b64decode(line.strip()).decode()
                if ":" in decoded:
                    combos.append(decoded)
            except Exception as e:
                print(f"[!] Skipping invalid base64 line: {line.strip()} ({e})")
    return combos

# Scan output grep for vulnerabilities
def grep_vulnerabilities():
    summary_file = os.path.join(BASE_FOLDER, "vulnerability_summary", f"vulns_{TIMESTAMP}.txt")
    vul_keywords = ["vulnerable", "CVE", "XSS", "SQL", "Injection", "default", "misconfiguration", "exploit"]
    with open(summary_file, "w") as summary:
        for folder in ["testssl_logs", "nikto_logs", "ffuf_logs", "ssh_audit_logs"]:
            folder_path = os.path.join(BASE_FOLDER, folder)
            for fname in os.listdir(folder_path):
                with open(os.path.join(folder_path, fname), "r", errors='ignore') as f:
                    for line in f:
                        if any(keyword.lower() in line.lower() for keyword in vul_keywords):
                            summary.write(f"[{fname}] {line}")

# Prepare and run tools
def prepare_and_run_scans(targets):
    if not any(targets.values()):
        print("[!] No open ports found for any scan, exiting.")
        sys.exit(1)

    if targets["ssl"]:
        testssl_cmds = [(f"testssl.sh --warnings batch {ip_port}", ip_port.replace(":", "_")) for ip_port in targets["ssl"]]
        run_parallel_scan(testssl_cmds, os.path.join(BASE_FOLDER, "testssl_logs"), "testssl")

    if targets["http"] or targets["https"]:
        nikto_cmds, ffuf_cmds, wafw00f_cmds = [], [], []
        for ip_port in targets["http"] + targets["https"]:
            ip, port = ip_port.split(":")
            url = f"http://{ip}:{port}"
            nikto_cmd = f"nikto -h {url}"
            ffuf_cmd = f"ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -of json -o {BASE_FOLDER}/ffuf_logs/{ip}_{port}_{TIMESTAMP}.json"
            wafw00f_cmd = f"wafw00f {url}"
            nikto_cmds.append((nikto_cmd, f"{ip}_{port}"))
            ffuf_cmds.append((ffuf_cmd, f"{ip}_{port}"))
            wafw00f_cmds.append((wafw00f_cmd, f"{ip}_{port}"))

        run_parallel_scan(nikto_cmds, os.path.join(BASE_FOLDER, "nikto_logs"), "nikto")
        run_parallel_scan(ffuf_cmds, os.path.join(BASE_FOLDER, "ffuf_logs"), "ffuf")
        run_parallel_scan(wafw00f_cmds, os.path.join(BASE_FOLDER, "wafw00f_logs"), "wafw00f")

    if targets["ssh"]:
        ssh_audit_cmds = [(f"ssh-audit {ip} -p {port}", f"{ip}_{port}") for ip_port in targets["ssh"] for ip, port in [ip_port.split(":")]]
        run_parallel_scan(ssh_audit_cmds, os.path.join(BASE_FOLDER, "ssh_audit_logs"), "ssh-audit")

        base64_creds_file = "creds.txt"
        combos = decode_creds(base64_creds_file)
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            for combo in combos:
                tmp.write(combo + "\n")
            combo_file_path = tmp.name

        hydra_cmds = [(f"hydra -C {combo_file_path} -s {port} {ip} ssh", f"{ip}_{port}") for ip_port in targets["ssh"] for ip, port in [ip_port.split(":")]]
        run_parallel_scan(hydra_cmds, os.path.join(BASE_FOLDER, "hydra_logs"), "hydra")

    grep_vulnerabilities()

def main():
    print("=== Automated Pentest Scanner (Nmap XML-based) ===")
    setup_folders()

    target_file = input(f"Enter target file path [default: {DEFAULT_TARGET_FILE}]: ").strip()
    if not target_file:
        target_file = DEFAULT_TARGET_FILE

    if not os.path.isfile(target_file):
        print(f"[!] Target file '{target_file}' not found.")
        sys.exit(1)

    try:
        batch_size = int(input("Enter batch size for scanning (e.g. 4): ").strip())
    except ValueError:
        print("[!] Invalid batch size entered.")
        sys.exit(1)

    xml_outputs = check_resume_scan()
    if not xml_outputs:
        xml_outputs = run_nmap_scan(target_file, batch_size)

    targets = parse_nmap_xml(xml_outputs)

    mode = input("Which scans do you want to run? [all/testssl/nikto/ffuf/ssh/none]: ").strip().lower()
    if mode == "all":
        prepare_and_run_scans(targets)
    elif mode == "none":
        print("[*] Only Nmap scan completed. Other scans skipped.")
    else:
        # Filter scan types
        if mode in ["testssl", "nikto", "ffuf", "ssh"]:
            filtered_targets = {k: v for k, v in targets.items() if k.startswith(mode)}
            prepare_and_run_scans(filtered_targets)
        else:
            print("[!] Unknown scan type.")

if __name__ == "__main__":
    main()

from pathlib import Path
# This helps handle file paths cleanly

from datetime import datetime
# This makes a timestamp for the report

import subprocess
# Lets us run Linux commands in Python

import socket
# Helps get local machine's IP


REPORTS_DIR = Path("reports")

def run_command(command):
# This is to help simplify instead of writing the same command logic over and over again
	try: 
		result = subprocess.check_output(command, shell=True, text=True).strip()
		return result
	except subprocess.CalledProcessError:
		return "ERROR"

def check_firewall():
	output = run_command("sudo ufw status")
	return "PASS" if "Status: active" in output else "FAIL"
# Checks if Firewall "ufw" is active


def check_ssh_root_login():
	output = run_command("grep '^PermitRootLogin' /etc/ssh/sshd_config")
	return "PASS" if "PermitRootLogin no" in output else "FAIL"
# Checks to see if root SSH login is disabled. Disabling root SSH loging helps improve Security 

def check_ssh_service():
	output = run_command("systemctl is-active ssh")
	return "PASS" if output == "active" else "FAIL"
# Checks to see if the SSH service is running. SSH is the remote admin mode in Linux

def get_os_version():
	output = run_command("cat /etc/os-release | grep PRETTY_NAME")
	return output if output != "ERROR" else "Unable to determine OS version"

def get_local_ip():
	try: 
		hostname = socket.gethostname()
		return socket.gethostbyname(hostname)
	except socket.gaierror:
		return "Unable to determine local IP"

def get_listening_ports():
	output = run_command("ss -tuln")
	return output if output != "ERROR" else "Unable to determine listening ports"
# runs ss -tuln  to show listening ports. This is important because it shows which services are exposed

def main():
	timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
	REPORTS_DIR.mkdir(exist_ok=True)
	report_path = REPORTS_DIR / f"security_audit_report_{timestamp}.txt"

	firewall_result = check_firewall()
	ssh_root_result = check_ssh_root_login()
	ssh_service_result = check_ssh_service()
	os_version = get_os_version()
	local_ip = get_local_ip()
	listening_ports = get_listening_ports()

	results = [
		("Firewall Enabled", firewall_result),
		("SSH Root Login Disabled", ssh_root_result),
		("SSH Service Running", ssh_service_result),
	]

	with open(report_path, "w") as report:
		report.write("Linux Security Baseline Audit Report\n")
		report.write(f"Generated: {datetime.now()}\n")
		report.write(f"Local Machine IP: {local_ip}\n")
		report.write(f"OS Version: {os_version}\n\n")

		report.write("Audit Results:\n")
		report.write("-" * 50 + "\n")
		for item, status in results:
			report.write(f"{item}: {status}\n")

		report.write("\nListening Ports:\n")
		report.write("-" * 50 + "\n")
		report.write(listening_ports + "\n")

	print("Security Baseline Audit Completed")
	print(f"Local Machine IP: {local_ip}")
	print(f"Report saved to: {report_path}")
	print("\nAudit Summary:")
	for item, status in results:
		print (f"{item}: {status}")

if __name__ == "__main__":
	main()

# Main ties the whole script together. It runs the checks, stores the results, writes the report, and then prints the summary

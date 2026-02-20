Basic Network Sniffer
Description
This project is a Basic Network Sniffer developed as part of my Cybersecurity Internship at CodeAlpha. The tool is designed to capture and analyze network traffic packets in real-time. It provides hands-on exposure to network security, protocol analysis, and data flow identification.

Features

Packet Capture: Captures live network traffic using the scapy library.


Protocol Identification: Analyzes and displays common protocols such as TCP, UDP, and ICMP.


IP Tracking: Displays the Source IP and Destination IP addresses for every captured packet.


Payload Analysis: Extracts and shows a snippet of the packet's payload for content inspection.

Prerequisites
Before running the script, ensure you have Python and the necessary library installed:

Bash
pip install scapy
Usage
Clone this repository.

Open your terminal or command prompt as an Administrator (required for packet sniffing).

Run the script:

Bash
python sniffer.py
The sniffer will start displaying packet details. Press Ctrl + C to stop.

Project Tasks Completed
As per the internship guidelines, this project covers the following:

Building a Python program for packet capture.

Analyzing packet structures and content.

Displaying IPs, protocols, and payloads.

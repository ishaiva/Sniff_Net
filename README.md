## Packet Analyzer for Termux

A lightweight packet capturing and analyzing script designed for use in Termux, with options to display packet data and save captured packets to a PCAP file, which can be analyzed using Wireshark.
Features:

    Displays packet data in a user-friendly format.
    Provides options for showing HEX and ASCII data of the packet.
    Captures every 100 packets and then prompts the user if they wish to continue.
    Saves captured packets to a PCAP file for further analysis.

 ## Installation:

    Ensure you have python3 and pip installed.

    Install the required libraries using pip:

    bash

    pip install scapy termcolor

## Usage:

    Run the script:

    bash

    python3 sniff.py

    Follow the on-screen prompts to:
       Choose the network interface.
       Decide whether to display the HEX and ASCII data of the packets.
       Specify the name for the PCAP output file.

    The script will capture packets and display them. After every 100 packets, it'll ask if you want to continue or stop. If stopped, the captured packets are saved to the specified PCAP file.

## Note:

This tool should be used responsibly. Ensure you have appropriate permissions before capturing network data. Unauthorized packet capturing may violate privacy laws or terms of service agreements.

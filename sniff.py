from scapy.all import sniff, IP, IPv6, Ether, wrpcap
import time
from termcolor import colored

class PacketAnalyzer:
    def __init__(self, interface, pcap_filename):
        self.interface = interface
        self.pcap_filename = pcap_filename
        self.max_width = 60
        self.delay = 0.25
        self.packet_count = 0
        self.packets = []

    def display_header(self):
        header = """
                                              .__  .__   
  ______ ____ _____  ______ ___.__.    _____  |  | |  |  
 /  ___// ___\\__  \ \____ <   |  |    \__  \ |  | |  |  
 \___ \\  \___ / __ \|  |_> >___  |     / __ \|  |_|  |__
/____  >\___  >____  /   __// ____| /\ (____  /____/____/
     \/     \/     \/|__|   \/      \/      \/           
        """
        print(colored(header, "cyan"))

    def print_separator(self):
        print("=" * self.max_width)

    def analyze_packet(self, packet, show_hex_ascii):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        ether_layer = packet.getlayer(Ether)
        if ether_layer:
            self.print_separator()
            print(colored(f" [+]---> Packet -> ({timestamp})", "red"))
            self.print_separator()
            src_mac = ether_layer.src
            dst_mac = ether_layer.dst
            print(colored(f" Source MAC: {src_mac}\n Destination MAC: {dst_mac}", "magenta"))

        ip_layer = packet.getlayer(IP)
        ipv6_layer = packet.getlayer(IPv6)

        if ip_layer:
            self.print_separator()
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            print(colored(f" Source IP: {src_ip}\n Destination IP: {dst_ip}", "green"))
        elif ipv6_layer:
            self.print_separator()
            src_ip = ipv6_layer.src
            dst_ip = ipv6_layer.dst
            print(colored(f" Source IPv6: {src_ip}\n Destination IPv6: {dst_ip}", "green"))

        transport_layer = packet.getlayer('TCP') or packet.getlayer('UDP')
        if transport_layer:
            self.print_separator()
            src_port = transport_layer.sport
            dst_port = transport_layer.dport
            protocol = transport_layer.name
            print(colored(f" Source Port: {src_port}\n Destination Port: {dst_port}\n Protocol: {protocol}", "cyan"))

        self.print_separator()

        if show_hex_ascii:
            hexdump = packet.original.hex()
            ascii_part = ''.join(
                colored(chr(int(hexdump[j:j + 2], 16)), "green") if 32 <= int(hexdump[j:j + 2], 16) <= 126 else colored('.', "red") for j in
                range(0, len(hexdump), 2))
            hex_ascii_width = self.max_width - 20
            hexdump_lines = [hexdump[i:i + hex_ascii_width] for i in range(0, len(hexdump), hex_ascii_width)]
            ascii_lines = [ascii_part[i:i + hex_ascii_width] for i in range(0, len(ascii_part), hex_ascii_width)]
            for hex_line, ascii_line in zip(hexdump_lines, ascii_lines):
                print(f" {hex_line.ljust(hex_ascii_width)} | {ascii_line}")
            self.print_separator()

        time.sleep(self.delay)

        self.packet_count += 1
        self.packets.append(packet)

        if self.packet_count % 100 == 0:
            self.ask_to_continue()

    def ask_to_continue(self):
        user_input = input(" [>] Continue capturing? (y/q): ").lower()
        if user_input == 'q':
            self.save_to_pcap()
            print(" [>] Capturing stopped.")
            exit(0)

    def save_to_pcap(self):
        wrpcap(self.pcap_filename, self.packets)
        print(f" [>] Packets saved to {self.pcap_filename}.")

    def start_capture(self, show_hex_ascii):
        self.display_header()
        sniff(iface=self.interface, prn=lambda p: self.analyze_packet(p, show_hex_ascii))

def main():
    print(" [>] Packet Analyzer!")
    interface = input(" [>] Enter the network interface (e.g., wlan0): ")
    show_hex_ascii = input(" [>] Show Hex and ASCII data? (y/n): ").lower() == 'y'
    pcap_filename = input(" [>] Enter the name for the PCAP file (e.g., capture.pcap): ")
    analyzer = PacketAnalyzer(interface, pcap_filename)
    analyzer.start_capture(show_hex_ascii)

if __name__ == "__main__":
    main()


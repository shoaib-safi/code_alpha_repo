from scapy.all import *
import logging
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import threading

# File mein logging setup karna (Setting up logging to a file)
logging.basicConfig(filename='network_sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables to keep track of packet statistics and captured packets
# Packet statistics aur captured packets ko track karne ke liye global variables
packet_count = 0
packet_types = {'TCP': 0, 'UDP': 0, 'IP': 0, 'HTTP': 0}
captured_packets = []  # Captured packets ko store karne ke liye list (List to store captured packets)

def analyze_packet(packet):
    """
    Captured packets ka analysis aur details ko log karne ka function.
    (Function to analyze captured packets and log details.)
    """
    global packet_count
    global packet_types
    global captured_packets

    packet_count += 1
    captured_packets.append(packet)  # Packet ko captured_packets list mein add karna (Append packet to captured_packets list)

    # Packet summary ko log karna (Log packet summary)
    summary = packet.summary()
    logging.info(f"Packet Summary: {summary}")

    # Full packet details ko log karna (Log full packet details)
    packet_details = packet.show(dump=True)
    logging.info(f"Full Packet Details:\n{packet_details}")

    # TCP packets ke details dikhana (Display TCP packet details)
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        logging.info(f"TCP Packet - Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
        packet_types['TCP'] += 1

    # UDP packets ke details dikhana (Display UDP packet details)
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        logging.info(f"UDP Packet - Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
        packet_types['UDP'] += 1

    # IP packets ke details dikhana (Display IP packet details)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        logging.info(f"IP Packet - Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")
        packet_types['IP'] += 1

    # Agar packet mein HTTP payload ho to analyze karna (Analyze HTTP payload if present)
    if packet.haslayer(Raw):
        raw_load = packet[Raw].load.decode(errors='ignore')
        if "HTTP" in raw_load:
            logging.info(f"HTTP Payload:\n{raw_load}")
            packet_types['HTTP'] += 1

    # GUI par statistics update karna (Update statistics on GUI)
    update_statistics()

def update_statistics():
    """
    GUI mein statistics update karne ka function.
    (Function to update statistics in the GUI.)
    """
    global packet_count
    global packet_types

    # GUI par packet statistics update karna (Update packet statistics on the GUI)
    stats_label.config(text=f"Total Packets: {packet_count}")
    tcp_label.config(text=f"TCP Packets: {packet_types['TCP']}")
    udp_label.config(text=f"UDP Packets: {packet_types['UDP']}")
    ip_label.config(text=f"IP Packets: {packet_types['IP']}")
    http_label.config(text=f"HTTP Packets: {packet_types['HTTP']}")

def start_sniffing(interface, count, filter_expr):
    """
    Packet sniffing start karne aur packet statistics dikhane ka function.
    (Function to start packet sniffing and display packet statistics.)
    """
    global captured_packets

    try:
        print(f"Sniffing on interface {interface} for {count} packets...")
        logging.info(f"Starting packet sniffing on interface {interface} for {count} packets with filter '{filter_expr}' at {datetime.now()}")

        # Packet sniffing ko start karna (Start packet sniffing)
        sniff(iface=interface, count=count, prn=analyze_packet, filter=filter_expr)

        # Sniffing complete hone ke baad message print karna (Print message after sniffing completes)
        print(f"Sniffing complete. Captured {count} packets.")
        logging.info(f"Packet sniffing completed at {datetime.now()}")

        # Captured packets ko CSV file mein export karna (Export captured packets to CSV file)
        with open('captured_packets.csv', 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['Packet Summary', 'Packet Details'])
            for packet in captured_packets:
                csv_writer.writerow([packet.summary(), packet.show(dump=True)])

    except Exception as e:
        logging.error(f"An error occurred: {e}")

def start_sniffing_thread():
    """
    Packet sniffing ko alag thread mein run karne ka function.
    (Function to run packet sniffing in a separate thread.)
    """
    interface = interface_entry.get()
    count = int(count_entry.get())
    filter_expr = filter_entry.get()
    threading.Thread(target=start_sniffing, args=(interface, count, filter_expr)).start()

def setup_gui():
    """
    Network sniffer ke liye GUI setup karne ka function.
    (Function to set up the GUI for the network sniffer.)
    """
    global stats_label, tcp_label, udp_label, ip_label, http_label

    # GUI window create karna (Create the GUI window)
    root = tk.Tk()
    root.title("Network Sniffer")

    # Network interface, packet count, aur filter expression ke input fields (Input fields for network interface, packet count, and filter expression)
    ttk.Label(root, text="Network Interface:").grid(column=0, row=0, padx=10, pady=5)
    global interface_entry
    interface_entry = ttk.Entry(root)
    interface_entry.grid(column=1, row=0, padx=10, pady=5)

    ttk.Label(root, text="Number of Packets:").grid(column=0, row=1, padx=10, pady=5)
    global count_entry
    count_entry = ttk.Entry(root)
    count_entry.grid(column=1, row=1, padx=10, pady=5)

    ttk.Label(root, text="BPF Filter Expression:").grid(column=0, row=2, padx=10, pady=5)
    global filter_entry
    filter_entry = ttk.Entry(root)
    filter_entry.grid(column=1, row=2, padx=10, pady=5)

    # Sniffing start karne ke liye button (Start button to begin sniffing)
    start_button = ttk.Button(root, text="Start Sniffing", command=start_sniffing_thread)
    start_button.grid(column=1, row=3, padx=10, pady=10)

    # Statistics display karne ke labels (Labels to display statistics)
    ttk.Label(root, text="Statistics:").grid(column=0, row=4, columnspan=2, padx=10, pady=10)
    stats_label = ttk.Label(root, text="Total Packets: 0")
    stats_label.grid(column=0, row=5, columnspan=2, padx=10, pady=5)

    tcp_label = ttk.Label(root, text="TCP Packets: 0")
    tcp_label.grid(column=0, row=6, columnspan=2, padx=10, pady=5)

    udp_label = ttk.Label(root, text="UDP Packets: 0")
    udp_label.grid(column=0, row=7, columnspan=2, padx=10, pady=5)

    ip_label = ttk.Label(root, text="IP Packets: 0")
    ip_label.grid(column=0, row=8, columnspan=2, padx=10, pady=5)

    http_label = ttk.Label(root, text="HTTP Packets: 0")
    http_label.grid(column=0, row=9, columnspan=2, padx=10, pady=5)

    # GUI ko run karna (Run the GUI)
    root.mainloop()

if __name__ == "__main__":
    # GUI setup function ko call karna (Call the GUI setup function)
    setup_gui()

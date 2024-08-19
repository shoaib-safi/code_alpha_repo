# Network Sniffer

## Description

This project is a basic network sniffer built in Python using the Scapy library.
 It captures and analyzes network traffic, providing detailed information about each packet and displaying real-time statistics through a graphical user interface (GUI).
 The tool is designed to help users monitor network activity and gain insights into the types of packets traveling through their network.

## Features

1. Capture and Analyze Network Packets: The sniffer captures packets transmitted over a network and performs an analysis to extract relevant information.
2. Display Statistics: Shows real-time statistics for different types of packets, including TCP, UDP, IP, and HTTP.
3. CSV Export: Captured packet summaries and details are saved to a CSV file for further examination.
4. GUI Interface: Provides a user-friendly graphical interface to start and manage packet sniffing activities.

## Requirements

1. Python 3.x: Ensure you have Python 3.x installed on your system. You can download it from the [official Python website](https://www.python.org/).
2. Scapy library: This is a Python library used for packet manipulation and analysis. It can be installed using the provided `requirements.txt` file.

## Setup

1. Clone or Download the Repository:
   - To clone the repository, use the following command in your terminal or command prompt:
     ```bash
     git clone <repository-url>
     ```
     Replace `<repository-url>` with the actual URL of the GitHub repository.
   - Alternatively, you can download the project files directly from the GitHub repository page and extract them to your local machine.

2. Install Required Libraries:
   - Open a terminal or command prompt.
   - Navigate to the project directory where `requirements.txt` is located. You can do this using the `cd` command:
     ```bash
     cd path/to/project-directory
     ```
     Replace `path/to/project-directory` with the actual path to your project directory.
   - Install the required libraries by running:
     ```bash
     pip install -r requirements.txt
     ```
     This command reads the `requirements.txt` file and installs all the libraries listed in it.

3. Run the Application:
   - Ensure you are still in the project directory.
   - Start the network sniffer application by executing the following command:
     ```bash
     python main.py
     ```
     This will launch the graphical user interface of the network sniffer.

## Usage

1. Network Interface: Enter the name of the network interface you want to sniff on (e.g., `eth0`, `wlan0`). This specifies which network adapter will be monitored for traffic.
2. Number of Packets: Enter the number of packets you want to capture. The sniffer will stop after capturing this number of packets.
3. BPF Filter Expression: Optionally, provide a BPF (Berkeley Packet Filter) expression to filter packets based on specific criteria (e.g., `tcp`, `udp port 80`).
4. Start Sniffing: Click the "Start Sniffing" button to begin capturing packets. The GUI will show real-time statistics and update as packets are captured.

## Files

1. `main.py`: This is the main script for the network sniffer application. It contains the code for packet capture, analysis, and GUI functionality.
2. `requirements.txt`: This file lists the required Python libraries for the project. Use this file to install dependencies.
3. `README.txt`: This file provides an overview of the project, setup instructions, and usage details.

## Logging

The application logs packet summaries, detailed information, and statistical updates to `network_sniffer.log`. 
This log file helps in tracking the sniffer's activity and analyzing captured data.

## CSV Export

Captured packets are saved to `captured_packets.csv` after sniffing is complete. 
This CSV file includes packet summaries and detailed information for offline review and analysis.

## License

This project is licensed under the MIT License. You can find the details of the license in the `LICENSE` file included in the repository.

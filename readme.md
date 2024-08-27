# Packet Sniffer

A graphical packet sniffer application built using Python and Tkinter, with the capability to capture, filter, and analyze network packets in real-time.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [UI Overview](#ui-overview)
- [Filtering Packets](#filtering-packets)
- [Saving and Loading Packets](#saving-and-loading-packets)
- [Viewing Packet Details](#viewing-packet-details)
- [Contributing](#contributing)
- [License](#license)

## Features

- Capture live network traffic using the Scapy library.
- Real-time packet display with protocol filtering options.
- Save captured packets to a file and load them for analysis.
- View detailed information about individual packets.
- Simple and intuitive user interface using Tkinter.

## Requirements

- Python 3.x
- `scapy`
- `netifaces`
- `tkinter` (included with Python on most platforms)

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/rash2020/packet-sniffer
    ```
2. **Navigate to the project directory**:
    ```bash
    cd packet-sniffer
    ```
3. **Install the required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```
   Ensure that `scapy` and `netifaces` are installed.

## Usage

1. **Run the application**:
    ```bash
    python packet_sniffer.py
    ```
2. **Start Sniffing**:
   - Click the "Start Sniffing" button to begin capturing packets.
3. **Stop Sniffing**:
   - Click the "Stop Sniffing" button to halt the packet capture.

## UI Overview

- **Packet Table**: Displays the captured packets with columns for Source, Destination, Protocol, Length, and Info.
- **Protocol Filter**: A dropdown to filter packets by protocol (TCP, UDP, ICMP, etc.).
- **Buttons**:
  - **Start Sniffing**: Starts capturing packets.
  - **Stop Sniffing**: Stops capturing packets.
  - **Save Packets to File**: Saves the captured packets in a `.pcap` file.
  - **Load Packets from File**: Loads packets from a `.pcap` file for analysis.
  - **View Packet Details**: Displays detailed information about a selected packet.
  - **View Statistics**: Shows statistics on the captured packets by protocol.

## Filtering Packets

- Use the protocol filter dropdown to select a specific protocol or view all packets.
- The table will update in real-time to display only the packets matching the selected protocol.

## Saving and Loading Packets

- **Saving**: Click the "Save Packets to File" button and choose a destination to save the packets in a `.pcap` file.
- **Loading**: Click the "Load Packets from File" button to load and display packets from an existing `.pcap` file.

## Viewing Packet Details

- Select a packet from the table and click the "View Packet Details" button to see the full packet information in a new window.

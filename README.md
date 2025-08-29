# Pcap File Parser using PcapPlusPlus

This project provides a C++ class for parsing pcap files with support for various network protocols including ICMP, ARP, UDP, TCP, IPv4, and IPv6. The parser outputs packet information in CSV format for easy analysis and processing.

## Prerequisites

- [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) library installed
- CMake (version 3.10 or higher)
- C++11 compatible compiler

## Installation

### Install PcapPlusPlus

#### macOS (using Homebrew)
```bash
brew install pcapplusplus
```

#### Linux (build from source)
```bash
git clone https://github.com/seladb/PcapPlusPlus.git
cd PcapPlusPlus
./configure-linux.sh
make
sudo make install
```

#### Windows
Please refer to [PcapPlusPlus documentation](https://pcapplusplus.github.io/docs/install/windows) for Windows installation instructions.

## Building the Project

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

```bash
./PcapParser <path_to_pcap_file> [output_csv_file]
```

Examples:
```bash
# Basic usage - output to console
./PcapParser example.pcap

# Output to CSV file
./PcapParser example.pcap output.csv
```

## Features

- Parses various network protocols:
  - Ethernet
  - IPv4/IPv6
  - ARP
  - TCP/UDP
  - ICMP
- **CSV Output**: Exports packet information to CSV format with proper formatting
- **Timestamp Precision**: Configurable timestamp precision (6 decimal places by default)
- **Packet Sequencing**: Includes packet sequence numbers in output
- **Protocol Analysis**: Detailed protocol-specific information including:
  - Source/destination MAC addresses
  - Source/destination IP addresses
  - Protocol types
  - Port numbers (for TCP/UDP)
  - Packet sizes
  - Time deltas between packets

## Project Structure

- `PcapParser.h` - Header file defining the parser class
- `PcapParser.cpp` - Implementation of the parser class with CSV output functionality
- `main.cpp` - Main program that handles command line arguments
- `CMakeLists.txt` - Build configuration file
- `README.md` - This documentation file

## License

This project is licensed under the MIT License.
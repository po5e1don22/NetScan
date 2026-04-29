# NetScan

NetScan is a tool for identifying network vulnerabilities based on JA3/JA3S TLS fingerprint analysis.

## Description

The core idea of the project is to collect and analyze JA3/JA3S fingerprints and compare them against a database of known fingerprints.

The program supports two operating modes:
- analysis of captured traffic (PCAP files)
- real-time traffic analysis (realtime mode)

Suricata is used as the traffic collection and processing engine.

The default fingerprint database contains 704 entries and can be extended by adding new ones.

## Features

- JA3/JA3S fingerprint analysis
- PCAP file processing
- real-time traffic monitoring
- fingerprint database matching
- extensible fingerprint database

## Dependencies

Required:
- suricata
- libglfw3-dev

Build tools:
- cmake
- g++

Install dependencies (Ubuntu/Debian):

```bash
sudo apt install suricata cmake libglfw3-dev g++
```

## Installation

Clone the repository (with submodules):

```bash
git clone --recurse-submodules https://github.com/po5e1don22/NetScan
cd NetScan
```

Build the project:

```bash
cmake -B build
cmake --build build
```

## Usage

PCAP analysis only:

```bash
./build/NetScan
```

PCAP + real-time mode:

```bash
sudo ./build/NetScan
```

## Notes
Superuser privileges are required for real-time traffic analysis
The fingerprint database can be extended by the user
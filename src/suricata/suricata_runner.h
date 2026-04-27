#pragma once
#include <string>

std::string run_suricata(const std::string& pcap_file, const std::string& output_dir);
std::string run_suricata_live(const std::string& base_output_dir, const std::string& interface);
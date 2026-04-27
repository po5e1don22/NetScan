#pragma once
#include <vector>
#include <string>
#include "ja3.h"

std::vector<JA3Record> parse_eve_json(const std::string& file_path);
std::vector<JA3Record> parse_eve_json_realtime(const std::string& file_path);
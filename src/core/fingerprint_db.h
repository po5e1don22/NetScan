#pragma once 

#include <string>
#include <unordered_map>

#include "ja3.h"

struct FingerprintMeta
{
    std::string ja3;
    std::string ja3s;

    std::string label;
    std::string category;
    std::string source;
    std::string notes;
};

std::unordered_map<std::string, FingerprintMeta> load_fingerprints(const std::string& path);
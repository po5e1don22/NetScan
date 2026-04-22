#pragma once 

#include <string>
#include <unordered_map>
#include <vector>

#include "ja3.h"

//fingerprint meta
struct FingerprintMeta
{
    std::string ja3;
    std::string ja3s;

    std::string label;
    std::string category;
    std::string source;
    std::string notes;
};

struct FingerprintDB
{
    std::unordered_map <std::string, FingerprintMeta> ja3_map; //only ja3 base 

    std::unordered_map <std::string, FingerprintMeta> ja3s_map; //only ja3s base

    std::vector<FingerprintMeta> full_pairs; //ja3 + ja3s
};

FingerprintDB load_fingerprints(const std::string& path);
#pragma once

#include "ja3.h"
#include <string>

bool add_unknown_fingerprint(
    const JA3Record& record,
    const std::string& label,
    const std::string& category,
    const std::string& notes,
    const std::string& db_path
);
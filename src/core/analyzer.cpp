#include "analyzer.h"
#include "ja3.h"
#include "third_party/json.hpp"

#include <fstream>
#include <iostream>

using json = nlohmann::json;

std::vector<JA3Record> parse_eve_json(const std::string& file_path)
{
    std::vector<JA3Record> results;

    std::ifstream file(file_path);
    if(!file.is_open())
    {
        std::cerr << "[ERROR] Cannot open file: " << file_path << std::endl;
        return results;
    }
    std::string line;

    while (std::getline(file, line))
    {
        try
        {
            json j = json::parse(line);

            if (j.contains("event_type") && j["event_type"] == "tls")
            {
                if (!j.contains("tls"))
                    continue;

                auto& tls = j["tls"];

                JA3Record record;

                // корень JSON
                if (j.contains("src_ip"))
                    record.src_ip = j["src_ip"];

                if (j.contains("dest_ip"))
                    record.dest_ip = j["dest_ip"];

                // tls блок
                if (tls.contains("ja3"))
                    record.ja3 = tls["ja3"]["hash"];

                if (tls.contains("ja3s"))
                    record.ja3s = tls["ja3s"]["hash"];

                if (tls.contains("sni"))
                    record.sni = tls["sni"];

                results.push_back(record);
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "[WARN] JSON parse error: " << e.what() << std::endl; 
        }
    }
    return results;
}

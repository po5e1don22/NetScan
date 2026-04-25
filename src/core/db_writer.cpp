#include "third_party/json.hpp"
#include "ja3.h"

#include <fstream>
#include <string>

using json = nlohmann::json;

bool add_unknown_fingerprint(
    const JA3Record& record,
    const std::string& label,
    const std::string& category,
    const std::string& notes,
    const std::string& db_path
)
{
    json db;

    // ================= LOAD =================
    std::ifstream in(db_path);
    if (in.is_open())
        in >> db;

    if (!db.is_array())
        db = json::array();

    // ================= DUP CHECK =================
    for (const auto& item : db)
    {
        if (!item.contains("fingerprint"))
            continue;

        const auto& fp = item["fingerprint"];

        std::string ja3 = fp.value("ja3", "");
        std::string ja3s = fp.value("ja3s", "");

        // FULL match
        if (!record.ja3.empty() && !record.ja3s.empty() &&
            ja3 == record.ja3 && ja3s == record.ja3s)
        {
            return false;
        }

        // JA3 match
        if (!record.ja3.empty() && ja3 == record.ja3)
        {
            return false;
        }

        // JA3S match
        if (!record.ja3s.empty() && ja3s == record.ja3s)
        {
            return false;
        }
    }

    // ================= CREATE ENTRY =================
    json entry = {
        {"fingerprint", {
            {"ja3", record.ja3},
            {"ja3s", record.ja3s}
        }},
        {"meta", {
            {"label", label},
            {"category", category.empty() ? "unknown" : category},
            {"source", "user_added"},
            {"notes", notes}
        }}
    };

    db.push_back(entry);

    // ================= SAVE =================
    std::ofstream out(db_path);
    if (!out.is_open())
        return false;

    out << db.dump(4);

    return true;
}
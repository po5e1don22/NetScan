#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>

//unique directory name generator 
std::string generate_output_dir (const std::string& base_dir)
{
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm local_time{};
    localtime_r(&time, &local_time);

    std::stringstream ss;
    ss <<base_dir << "/run_" << std::put_time(&local_time, "%Y-%m-%d_%H-%M-%S");
    return ss.str();
}

bool run_suricata(const std::string& pcap_file, const std::string& base_output_dir)
{
    std::string output_dir = generate_output_dir(base_output_dir);

    try //create output folder if not exist
    {
        if (!std::filesystem::exists(output_dir))
        {
            std::filesystem::create_directories(output_dir);
            std::cout << "[INFO] Created output directory: " << output_dir << std::endl;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "[ERROR] Faild to create directory: " << e.what() << std::endl;
        return false;
    }

    //suricata run command 
    std::string command = "suricata -r " + pcap_file + " -l " + output_dir;

    std::cout << "[INFO] Running: " << command << std::endl;
    int result = std::system(command.c_str());

    if (result !=0)
    {
        std::cerr << "[ERROR] Suricata failed with code:" << result << std::endl;
        return false;
    }
    return true;
}
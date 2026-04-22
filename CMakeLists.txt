cmake_minimum_required(VERSION 3.20)
project (NetScan)

set (SOURCES
    src/main.cpp
    src/suricata/suricata_runner.cpp
    src/core/analyzer.cpp
    src/core/fingerprint_db.cpp
    src/core/matcher.cpp
    src/core/db_writer.cpp
    src/core/unknown_queue.cpp
    src/core/queue_worker.cpp)

add_executable(NetScan ${SOURCES})

target_include_directories(NetScan PRIVATE src)
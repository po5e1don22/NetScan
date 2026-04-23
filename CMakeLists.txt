cmake_minimum_required(VERSION 3.20)
project (NetScan)

set (IMGUI_SOURCES
    src/third_party/imgui/imgui.cpp
    src/third_party/imgui/imgui_draw.cpp
    src/third_party/imgui/imgui_tables.cpp
    src/third_party/imgui/imgui_widgets.cpp
    src/third_party/imgui/backends/imgui_impl_glfw.cpp
    src/third_party/imgui/backends/imgui_impl_opengl3.cpp)

set (SOURCES
    src/main.cpp

    src/suricata/suricata_runner.cpp
    src/core/analyzer.cpp
    src/core/fingerprint_db.cpp
    src/core/matcher.cpp
    src/core/db_writer.cpp
    src/core/unknown_queue.cpp
    src/core/queue_worker.cpp
    src/gui/gui_runner.cpp
    src/app/app.cpp)

add_executable(NetScan 
    ${SOURCES}
    ${IMGUI_SOURCES})

target_include_directories(NetScan
    PRIVATE
        src
        src/third_party/imgui
        src/third_party/imgui/backends)

find_package(glfw3 REQUIRED)
find_package(OpenGL REQUIRED)

target_link_libraries(NetScan PRIVATE glfw OpenGL::GL)
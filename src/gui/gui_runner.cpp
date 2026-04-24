#include <cstring>
#include <string>

#include "gui_runner.h"
#include "gui_state.h"
#include "app/app.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "ImGuiFileDialog.h"

#include <GLFW/glfw3.h>
#include <thread>

int run_gui()
{
    glfwInit();
    glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);
    glClearColor(0.0f, 0.0f, 0.0f, 0.0f);

    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    GLFWwindow* window = glfwCreateWindow(1920, 1080, "NetScan", nullptr, nullptr);
    glfwMakeContextCurrent(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    GUIState state;

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("NetScan");

        if (ImGuiFileDialog::Instance()->Display("ChoosePCAP"))
        {
            if (ImGuiFileDialog::Instance()->IsOk())
            {
                std::string path = ImGuiFileDialog::Instance()->GetFilePathName();

                strncpy(state.pcap_path, path.c_str(), sizeof(state.pcap_path));
                state.pcap_path[sizeof(state.pcap_path) - 1] = '\0';
            }

            ImGuiFileDialog::Instance()->Close();
        }

        if (ImGui::Button("Open PCAP"))
        {
            ImGuiFileDialog::Instance()->OpenDialog(
                "ChoosePCAP",
                "Select PCAP file",
                ".pcap,.pcapng"
            );
        }

        ImGui::Text("Selected: %s", state.pcap_path);
        if (ImGui::Button("Start Scan") && !state.scan_running)
        {
            if (strlen(state.pcap_path) == 0)
                    return 0;

                state.scan_running = true;

                std::thread([&state]()
                {
                    std::string out_dir;

                    if (!run_suricata_stage(std::string(state.pcap_path), out_dir))
                    {
                        state.scan_running = false;
                        return;
                    }

                    auto result = parse_stage(out_dir + "/eve.json");

                    state.records = result.records;

                    auto db = load_db();
                    state.matches = match_stage(result, db);

                    state.scan_running = false;

                }).detach();
            }

        //статус
        if (state.scan_running)
            ImGui::Text("Scanning...");

        // вывод
        ImGui::Separator();
        for (const auto& m : state.matches)
        {
            // 👉 Цвет по типу совпадения
            ImVec4 color;
            const char* tag;

            if (m.match_type == "FULL")
            {
                color = ImVec4(0, 1, 0, 1);
                tag = "[FULL]";
            }
            else if (m.match_type == "WEAK_JA3")
            {
                color = ImVec4(1, 1, 0, 1);
                tag = "[JA3]";
            }
            else if (m.match_type == "WEAK_JA3S")
            {
                color = ImVec4(1, 0.5f, 0, 1);
                tag = "[JA3S]";
            }
            else
            {
                color = ImVec4(1, 0, 0, 1);
                tag = "[UNKNOWN]";
            }

            // 👉 Верхняя строка (IP + тип)
            ImGui::Text("%s -> %s", 
                m.src_ip.c_str(), 
                m.dest_ip.c_str());

            ImGui::SameLine();
            ImGui::TextColored(color, "%s", tag);

            // 👉 Детали
            ImGui::Indent();

            ImGui::Text("JA3: %s", m.ja3.c_str());
            ImGui::Text("JA3S: %s", m.ja3s.c_str());

            // 👉 Категория (если есть)
            if (!m.category.empty())
                ImGui::Text("Category: %s", m.category.c_str());

            // 👉 Label (если есть)
            if (!m.label.empty())
                ImGui::Text("Label: %s", m.label.c_str());

            ImGui::Unindent();

            ImGui::Separator();
        }

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    return 0;
}
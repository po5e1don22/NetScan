#include "gui_runner.h"
#include "gui_state.h"
#include "app/app.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>
#include <thread>

int run_gui()
{
    glfwInit();
    GLFWwindow* window = glfwCreateWindow(900, 600, "NetScan", nullptr, nullptr);
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

        // 👉 ввод пути
        ImGui::InputText("PCAP", state.pcap_path, sizeof(state.pcap_path));

        // 👉 кнопка
        if (ImGui::Button("Start Scan") && !state.scan_running)
        {
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
                match_stage(result, db);

                state.scan_running = false;

            }).detach();
        }

        // 👉 статус
        if (state.scan_running)
            ImGui::Text("Scanning...");

        // 👉 вывод
        ImGui::Separator();
        for (const auto& r : state.records)
        {
            ImGui::Text("%s -> %s | JA3: %s",
                r.src_ip.c_str(),
                r.dest_ip.c_str(),
                r.ja3.c_str());
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
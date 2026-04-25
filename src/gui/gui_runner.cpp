#include <cstring>
#include <string>
#include <thread>
#include <mutex>

#include "gui_runner.h"
#include "gui_state.h"
#include "app/app.h"
#include "core/db_writer.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "ImGuiFileDialog.h"

#include <GLFW/glfw3.h>

int run_gui()
{
    glfwInit();
    glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);

    GLFWwindow* window = glfwCreateWindow(1920, 1080, "NetScan", nullptr, nullptr);
    glfwMakeContextCurrent(window);

    glClearColor(0.0f, 0.0f, 0.0f, 0.0f);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    GUIState state;
    std::mutex state_mutex;

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("NetScan");

        ImGui::SameLine(ImGui::GetWindowWidth() - 50);

        if (ImGui::Button("CLose"))
        {
            glfwSetWindowShouldClose(window, true);
}

        // ================= FILE DIALOG =================
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

        // ================= START SCAN =================
        bool can_run = strlen(state.pcap_path) > 0;

        if (!can_run)
        {
            ImGui::TextColored(ImVec4(1,0,0,1), "Select PCAP file first");
        }
        else if (ImGui::Button("Start Scan") && !state.scan_running)
        {
            state.scan_running = true;

            std::thread([&state, &state_mutex]()
            {
                std::string out_dir;

                if (!run_suricata_stage(std::string(state.pcap_path), out_dir))
                {
                    state.scan_running = false;
                    return;
                }

                auto result = parse_stage(out_dir + "/eve.json");
                auto db = load_db();
                auto matches = match_stage(result, db);

                {
                    std::lock_guard<std::mutex> lock(state_mutex);
                    state.matches = std::move(matches);
                }

                state.scan_running = false;

            }).detach();
        }

        if (state.scan_running)
            ImGui::Text("Scanning...");

        ImGui::Separator();

        // ================= TABLE =================
        bool open_popup = false;

        if (ImGui::BeginTable("ResultsTable", 7,
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_Sortable |
            ImGuiTableFlags_ScrollY))
        {
            ImGui::TableSetupColumn("Src IP");
            ImGui::TableSetupColumn("Dst IP");
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("JA3");
            ImGui::TableSetupColumn("JA3S");
            ImGui::TableSetupColumn("Category");
            ImGui::TableSetupColumn("Label");
            ImGui::TableHeadersRow();

            for (int i = 0; i < (int)state.matches.size(); i++)
            {
                const auto& m = state.matches[i];

                ImGui::TableNextRow();
                ImGui::PushID(i);

                ImGui::TableSetColumnIndex(0);

                bool row_clicked = ImGui::Selectable(
                    "##row",
                    false,
                    ImGuiSelectableFlags_SpanAllColumns
                );

                if (row_clicked && m.match_type == "UNKNOWN")
                {
                    state.selected_index = i;

                    state.input_label[0] = '\0';
                    state.input_category[0] = '\0';
                    state.input_notes[0] = '\0';

                    open_popup = true;
                }

                ImGui::SameLine();
                ImGui::TextUnformatted(m.src_ip.c_str());

                ImVec4 color;
                if (m.match_type == "FULL")
                    color = ImVec4(0,1,0,1);
                else if (m.match_type == "WEAK_JA3")
                    color = ImVec4(1,1,0,1);
                else if (m.match_type == "WEAK_JA3S")
                    color = ImVec4(1,0.5f,0,1);
                else
                    color = ImVec4(1,0,0,1);

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", m.dest_ip.c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(color, "%s", m.match_type.c_str());

                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", m.ja3.c_str());

                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", m.ja3s.c_str());

                ImGui::TableSetColumnIndex(5);

                ImVec4 col = GetCategoryColor(m.category);
                ImGui::PushStyleColor(ImGuiCol_Text, col);

                ImGui::Text("%s", m.category.c_str());

                ImGui::PopStyleColor();

                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%s", m.label.c_str());

                ImGui::PopID();
            }

            ImGui::EndTable();
        }

        // ================= OPEN POPUP =================
        if (open_popup)
        {
            ImGui::OpenPopup("Add Fingerprint");
        }

        // ================= POPUP =================
        if (ImGui::BeginPopupModal("Add Fingerprint", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
        {
            ImGui::Text("Add new fingerprint");

            ImGui::InputText("Label", state.input_label, sizeof(state.input_label));
            int category_index = 0;

            for (int i = 0; i < 3; i++)
            {
                if (strcmp(state.input_category, CATEGORY_ITEMS[i]) == 0)
                {
                    category_index = i;
                    break;
                }
            }

            ImVec4 col = GetCategoryColor(CATEGORY_ITEMS[category_index]);

            ImGui::PushStyleColor(ImGuiCol_Text, col);

            if (ImGui::BeginCombo("##category_combo", CATEGORY_ITEMS[category_index]))
            {
                for (int i = 0; i < 3; i++)
                {
                    bool selected = (category_index == i);

                    ImVec4 item_col = GetCategoryColor(CATEGORY_ITEMS[i]);
                    ImGui::PushStyleColor(ImGuiCol_Text, item_col);

                    if (ImGui::Selectable(CATEGORY_ITEMS[i], selected))
                        category_index = i;

                    ImGui::PopStyleColor();

                    if (selected)
                        ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }
            ImGui::PopStyleColor();
            ImGui::SameLine();
            
            ImGui::Text("Category");

            strncpy(state.input_category, CATEGORY_ITEMS[category_index],
            sizeof(state.input_category));

            ImGui::InputText("Notes", state.input_notes, sizeof(state.input_notes));

            if (ImGui::Button("Save"))
            {
                if (state.selected_index >= 0)
                {
                    const auto& m = state.matches[state.selected_index];

                    JA3Record r;
                    r.ja3 = m.ja3;
                    r.ja3s = m.ja3s;

                    bool added = add_unknown_fingerprint(
                        r,
                        state.input_label,
                        state.input_category,
                        state.input_notes,
                        "data/fingerprints.json"
                );

                    state.matches[state.selected_index].label = state.input_label;
                    state.matches[state.selected_index].category = state.input_category;
                    state.matches[state.selected_index].match_type = "FULL";
                }

                ImGui::CloseCurrentPopup();
            }

            ImGui::SameLine();

            if (ImGui::Button("Cancel"))
                ImGui::CloseCurrentPopup();

            ImGui::EndPopup();
        }
        ImGui::End();

        // ================= RENDER =================
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
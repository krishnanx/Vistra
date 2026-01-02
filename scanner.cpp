#include <yara.h>
#include <yara/compiler.h> 
#include <iostream>
#include <fstream>      // For file output (reporting)
#include <filesystem>
#include <map>
#include <cstring>
#include <string>
#include <ctime>        // For timestamp in report

namespace fs = std::filesystem;

// Explicitly define the constant if <yara/compiler.h> doesn't expose it correctly
#ifndef YR_COMPILER_ERROR
#define YR_COMPILER_ERROR 2 
#endif 

/* Global scan state (reset per file) */
int total_severity = 0;
std::string suggested_action = "ignore";
std::map<std::string, int> matched_rules;
std::string final_decision_text = "[OK] CLEAN FILE"; // New global for reporting

/* ---------------- YARA CALLBACK (Unchanged) ---------------- */
// ... (yara_callback remains the same)
int yara_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;

        int severity = 0;
        std::string action = "ignore";

        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (strcmp(meta->identifier, "severity") == 0 &&
                meta->type == META_TYPE_INTEGER) {
                severity = meta->integer;
            }
            if (strcmp(meta->identifier, "action") == 0 &&
                meta->type == META_TYPE_STRING) {
                action = meta->string;
            }
        }

        total_severity += severity;
        matched_rules[rule->identifier] = severity;

        if (action != "ignore") {
            suggested_action = action;
        }

        std::cout << "  [+] Matched rule: "
                  << rule->identifier
                  << " | severity=" << severity
                  << " | action=" << action
                  << std::endl;
    }
    return CALLBACK_CONTINUE;
}

/* ---------------- QUARANTINE / DELETED MOVE ---------------- */

// New function for moving files to a specific destination folder
void move_file_to_folder(const fs::path& file, const std::string& folder_name) {
    fs::create_directory(folder_name);
    fs::path dest = fs::path(folder_name) / file.filename();

    try {
        fs::rename(file, dest);
        std::cout << "  [→] Moved to " << folder_name << "\n";
    } catch (...) {
        std::cerr << "  [!] Failed to move file to " << folder_name << "\n";
    }
}

// Renamed and repurposed the old quarantine function
void quarantine_file(const fs::path& file) {
    move_file_to_folder(file, "Quarantine");
}

// New function to simulate deletion by moving to a "Deleted" folder
void delete_file_simulated(const fs::path& file) {
    move_file_to_folder(file, "Deleted");
}


/* ---------------- REPORTING ---------------- */

void write_report(const fs::path& file) {
    fs::create_directory("Reports");
    std::string report_filename = "Reports/" + file.filename().string() + "_report.txt";
    std::ofstream report_file(report_filename);

    // Get current time
    time_t rawtime;
    struct tm * timeinfo;
    char buffer[80];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::string timestamp(buffer);


    report_file << "##########################################\n";
    report_file << "## YARA SCAN REPORT\n";
    report_file << "##########################################\n";
    report_file << "Scan Time:     " << timestamp << "\n";
    report_file << "File Scanned:  " << file.string() << "\n";
    report_file << "File Size:     " << fs::file_size(file) << " bytes\n";
    report_file << "------------------------------------------\n";
    report_file << "Decision:      " << final_decision_text << "\n";
    report_file << "Total Severity:" << total_severity << "\n";
    report_file << "Action Taken:  ";

    if (total_severity >= 150) {
        report_file << "Moved to Deleted (Simulated Delete)\n";
    } else if (total_severity >= 70 || suggested_action == "quarantine") {
        report_file << "Moved to Quarantine\n";
    } else {
        report_file << "Ignored (Clean)\n";
    }

    if (!matched_rules.empty()) {
        report_file << "\nMATCHED RULES:\n";
        for (const auto& r : matched_rules) {
            report_file << "  - Rule: " << r.first 
                        << " | Severity: " << r.second << "\n";
        }
    } else {
        report_file << "\nNo rules matched.\n";
    }
    report_file << "##########################################\n";

    std::cout << "  [✓] Report saved to " << report_filename << "\n";
}


/* ---------------- YARA COMPILER CALLBACK (Unchanged) ---------------- */
// ... (Compiler callback struct and function are moved here)

struct CompilerErrorInfo {
    std::string message;
    std::string rule_file;
    int line = 0;
    bool had_error = false;
};

CompilerErrorInfo g_compiler_error;

void compiler_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule, 
    const char* message,
    void* user_data
) {
    if (error_level == YR_COMPILER_ERROR && !g_compiler_error.had_error) {
        g_compiler_error.message = message;
        g_compiler_error.rule_file = file_name ? file_name : "N/A"; 
        g_compiler_error.line = line_number;
        g_compiler_error.had_error = true;
        (void)rule; 
    }
}


/* ---------------- MAIN ---------------- */

/* ---------------- MAIN (FINAL CORRECTED LOGIC) ---------------- */

int main() {
    const std::string SCAN_DIR = "Files";
    const std::string RULE_DIR = "Yara";

    if (!fs::exists(SCAN_DIR)) {
        std::cerr << "[!] Files directory not found\n";
        return 1;
    }

    if (!fs::exists(RULE_DIR)) {
        std::cerr << "[!] Yara rule directory not found\n";
        return 1;
    }

    yr_initialize();

    YR_COMPILER* compiler = nullptr;
    yr_compiler_create(&compiler);
    
    yr_compiler_set_callback(compiler, compiler_callback, nullptr);

    /* Load YARA rules (Unchanged logic) */
    for (const auto& rule : fs::directory_iterator(RULE_DIR)) {
        if (!rule.is_regular_file()) continue;
        g_compiler_error.had_error = false;
        
        FILE* fp = fopen(rule.path().c_str(), "r");
        if (!fp) continue;
        
        const char* rule_path_c_str = rule.path().c_str(); 

       int res = yr_compiler_add_file(
            compiler, 
            fp, 
            nullptr, 
            rule_path_c_str
        );
        
        fclose(fp);

        if (res != ERROR_SUCCESS || g_compiler_error.had_error) {
            std::cerr << "\n[!!!] FAILED TO COMPILE RULE\n";
            std::cerr << "[!] File: " << rule.path() << " | Error Code: " << res << std::endl;
            
            if (g_compiler_error.had_error) { 
                std::cerr << "    Compilation Error: "
                          << g_compiler_error.message
                          << " on line " << g_compiler_error.line
                          << " (In file: " << g_compiler_error.rule_file << ")"
                          << std::endl;
            } else {
                 std::cerr << "    Note: Rule failed compilation, but no specific error message was captured. Rule may contain invalid characters.\n";
            }
            
            yr_compiler_destroy(compiler);
            yr_finalize();
            return 1; 
        }
    }


    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS || !rules) {
        if (!g_compiler_error.had_error) {
             std::cerr << "[!] Could not finalize rules. Check rule files.\n";
        }
       
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }
    
    yr_compiler_destroy(compiler);


    /* Scan files (CENTRALIZED REPORTING AND ACTION) */
    for (const auto& file : fs::directory_iterator(SCAN_DIR)) {
        if (!file.is_regular_file()) continue;

        // 1. Reset variables
        total_severity = 0;
        suggested_action = "ignore";
        matched_rules.clear();
        final_decision_text = "[OK] CLEAN FILE"; 

        std::cout << "\n[*] Scanning: " << file.path() << std::endl;

        // Perform the scan (This was missing from the code you showed in the last turn)
        yr_rules_scan_file(
            rules,
            file.path().c_str(),
            0,
            yara_callback,
            nullptr,
            0
        );

        // 2. Determine the decision and set final text
        bool needs_action = true;
        
        if (total_severity >= 150) {
            final_decision_text = "[!!!] CONFIRMED RANSOMWARE → DELETE";
        }
        else if (total_severity >= 70 || suggested_action == "quarantine") {
            final_decision_text = "[!!] SUSPICIOUS FILE → QUARANTINE";
        }
        else {
            needs_action = false;
        }

        // 3. Print summary to console
        std::cout << final_decision_text << "\n";
        if (!matched_rules.empty()) {
            std::cout << "     Matched rules:\n";
            for (const auto& r : matched_rules) {
                std::cout << "       - "
                          << r.first
                          << " (severity " << r.second << ")\n";
            }
        }
        
        // 4. Write the report (MUST HAPPEN BEFORE THE FILE MOVE)
        write_report(file.path());

        // 5. Take the final action
        if (total_severity >= 150) {
            delete_file_simulated(file.path()); // Move to Deleted folder
        }
        else if (needs_action) { // Only quarantine if action was recommended
            quarantine_file(file.path()); // Move to Quarantine folder
        }
        // If clean, no move action is taken.
    }

    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}
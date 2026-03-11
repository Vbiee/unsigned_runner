//
// unsigned_runner.cpp
// Manages file signing workflows: scan/collect unsigned PE files, restore signed files.
// Requires: Windows SDK, C++17, link with Wintrust.lib
//
// Compile (MSVC example):
//   cl /std:c++17 /EHsc unsigned_runner.cpp /link Wintrust.lib
//

#include "courier.h"

// ---------------------------------------------------------------------------
// Console UI
// ---------------------------------------------------------------------------

static void EnableAnsiConsole()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void PrintMenu()
{
    const char* RESET  = "\033[0m";
    const char* BOLD   = "\033[1m";
    const char* DIM    = "\033[2m";
    const char* CYAN   = "\033[38;2;0;210;210m";
    const char* YELLOW = "\033[38;2;255;200;0m";
    const char* WHITE  = "\033[38;2;230;230;230m";
    const char* GRAY   = "\033[38;2;100;100;110m";
    const char* BG_DARK= "\033[48;2;18;18;24m";
    const char* GREEN  = "\033[38;2;80;220;120m";
    const char* ORANGE = "\033[38;2;255;140;0m";
    const char* RED    = "\033[38;2;220;80;80m";

    std::cout
        << "\n"
        << BG_DARK << CYAN << BOLD
        << "  \xc9\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xbb\n"
        << "  \xba" << YELLOW << "   \xe2\x9c\xa6  PE FILE SIGNING WORKFLOW  \xe2\x9c\xa6   " << CYAN << "\xba\n"
        << "  \xc7\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xb6\n"
        << "  \xba  " << GREEN  << BOLD << " 1 " << RESET << BG_DARK << WHITE << "  Scan & Collect unsigned PE files    " << CYAN << "\xba\n"
        << "  \xba  " << RESET  << BG_DARK << GRAY << DIM << "     EXE / DLL / SYS \xbb Pending_Sign\\ " << RESET << BG_DARK << CYAN << "  \xba\n"
        << "  \xba                                          \xba\n"
        << "  \xba  " << YELLOW << BOLD << " 2 " << RESET << BG_DARK << WHITE << "  Restore signed files to origin      " << CYAN << "\xba\n"
        << "  \xba  " << RESET  << BG_DARK << GRAY << DIM << "     Pending_Sign\\ \xbb original paths     " << RESET << BG_DARK << CYAN << "  \xba\n"
        << "  \xba                                          \xba\n"
        << "  \xba  " << ORANGE << BOLD << " 3 " << RESET << BG_DARK << WHITE << "  Scan & Report only (no collection)  " << CYAN << "\xba\n"
        << "  \xba  " << RESET  << BG_DARK << GRAY << DIM << "     SYS flagged if not by Microsoft  " << RESET << BG_DARK << CYAN << "  \xba\n"
        << "  \xba                                          \xba\n"
        << "  \xba  " << RED    << BOLD << " 0 " << RESET << BG_DARK << WHITE << "  Exit                                " << CYAN << "\xba\n"
        << "  \xc8\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xbc\n"
        << RESET
        << "  " << CYAN << "\xbb " << RESET << WHITE << "Choice: " << RESET;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    EnableAnsiConsole();

    std::string choice;
    while (true)
    {
        PrintMenu();
        std::getline(std::cin, choice);
        std::cout << "\n";

        if      (choice == "1") RunScanAndCollect();
        else if (choice == "2") RunRestoreSigned();
        else if (choice == "0") { std::cout << "  Bye.\n\n"; break; }
        else    std::cerr << "  \033[38;2;220;80;80m[!] Invalid choice.\033[0m\n";

        std::cout << "\n";
    }

    return 0;
}

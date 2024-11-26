/*
 * MIT License
 *
 * Copyright (c) 2024 Dominik Protasewicz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// System includes
#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <filesystem>
#include <numeric>
#include <numbers>
#include <cmath>
#include <cstdint>

// 3rd party includes
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "yaml-cpp/yaml.h"
#include "safetyhook.hpp"

// Local includes
#include "utils.hpp"

// Defines
#define VERSION "3.0.0"

// Macros
#define LOG(STRING, ...) spdlog::info("{} : " STRING, __func__, ##__VA_ARGS__)

// .yml to struct
typedef struct resolution_t {
    int width;
    int height;
    float aspectRatio;
} resolution_t;
typedef struct fov_t {
    bool enable;
    float value;
} fov_t;

typedef struct fix_t {
    fov_t fov;
} fix_t;

typedef struct yml_t {
    std::string name;
    bool masterEnable;
    resolution_t resolution;
    fix_t fix;
} yml_t;

// Globals
HMODULE baseModule = GetModuleHandle(NULL);
YAML::Node config = YAML::LoadFile("BorderlandsGOTYEnhancedFix.yml");
yml_t yml;

float nativeAspectRatio = 16.0f / 9.0f;

/**
 * @brief Initializes logging for the application.
 *
 * This function performs the following tasks:
 * 1. Initializes the spdlog logging library and sets up a file logger.
 * 2. Retrieves and logs the path and name of the executable module.
 * 3. Logs detailed information about the module to aid in debugging.
 *
 * @return void
 */
void logInit() {
    // spdlog initialisation
    auto logger = spdlog::basic_logger_mt("BorderlandsGOTYEnhanced", "BorderlandsGOTYEnhancedFix.log", true);
    spdlog::set_default_logger(logger);
    spdlog::flush_on(spdlog::level::debug);

    // Get game name and exe path
    WCHAR exePath[_MAX_PATH] = { 0 };
    GetModuleFileNameW(baseModule, exePath, MAX_PATH);
    std::filesystem::path exeFilePath = exePath;
    std::string exeName = exeFilePath.filename().string();

    // Log module details
    LOG("-------------------------------------");
    LOG("Compiler: {:s}", Utils::getCompilerInfo().c_str());
    LOG("Compiled: {:s} at {:s}", __DATE__, __TIME__);
    LOG("Version: {:s}", VERSION);
    LOG("Module Name: {:s}", exeName.c_str());
    LOG("Module Path: {:s}", exeFilePath.string().c_str());
    LOG("Module Addr: 0x{:x}", (uintptr_t)baseModule);
}

/**
 * @brief Reads and parses configuration settings from a YAML file.
 *
 * This function performs the following tasks:
 * 1. Reads general settings from the configuration file and assigns them to the `yml` structure.
 * 2. Initializes global settings if certain values are missing or default.
 * 3. Logs the parsed configuration values for debugging purposes.
 *
 * @return void
 */
void readYml() {
    yml.name = config["name"].as<std::string>();

    yml.masterEnable = config["masterEnable"].as<bool>();

    yml.resolution.width = config["resolution"]["width"].as<int>();
    yml.resolution.height = config["resolution"]["height"].as<int>();

    yml.fix.fov.enable = config["fixes"]["fov"]["enable"].as<bool>();
    yml.fix.fov.value = config["fixes"]["fov"]["value"].as<float>();

    // Initialize globals
    if (yml.resolution.width == 0 || yml.resolution.height == 0) {
        std::pair<int, int> dimensions = Utils::GetDesktopDimensions();
        yml.resolution.width  = dimensions.first;
        yml.resolution.height = dimensions.second;
    }
    yml.resolution.aspectRatio = (float)yml.resolution.width / (float)yml.resolution.height;

    LOG("Name: {}", yml.name);
    LOG("MasterEnable: {}", yml.masterEnable);
    LOG("Resolution.Width: {}", yml.resolution.width);
    LOG("Resolution.Height: {}", yml.resolution.height);
    LOG("Resolution.AspectRatio: {}", yml.resolution.aspectRatio);
    LOG("Fix.Fov.Enable: {}", yml.fix.fov.enable);
    LOG("Fix.Fov.Value: {}", yml.fix.fov.value);
}

/**
 * @brief Applies a resolution fix by hooking and patching specific memory patterns.
 *
 * This function performs the following tasks:
 * 1. Logs the current desktop resolution and aspect ratio.
 * 2. Places hooks at `patternFind0` and `patternFind1`.
 * 3. Patches two memory addresses at `resWidthAddrPatch` and `resHeightAddrPatch`.
 *
 * @details
 * The function first logs the desktop resolution and aspect ratio for debugging purposes.
 * It places hooks at `patternFind0` and `patternFind1` where the RAX register shall be
 * overwritten with the target width and height parameters in the configuration file. And will
 * also patch two memory addresses at `resWidthAddrPatch` and `resHeightAddrPatch` also using the
 * target width and height parameters in the configuration file.
 *
 * The hooking and patching is only performed if the `masterEnable` flag is set to `true`.
 *
 * How was this found?
 * Hooking for `patternFind0` and `patternFind1`:
 * The initial hooks in place were located when scanning for memory changes using cheat engine
 * when resolution changes took place in the game. The game's binary used a lot of memory
 * locations to store the new applied resolution. Each memory location was inspected to see
 * what instruction was writing or accessing it and eventually and with enough back tracking
 * I found where the resolution was converted from a string to a long value.
 * The code would call `ucrtbase.wtol`, a function from the Universal C Runtime (UCRT) library
 * in Windows from the ucrtbase.dll file. The `wtol` function is used to convert a wide-character
 * string (i.e., a string of `wchar_t` characters, which are typically used for Unicode text)
 * to a long integer. After the call to this function the long value would be placed in the RAX
 * register and then the game would mov the value from the RAX register to the R15/R12 register
 * for width/height respectively.
 * Relevent code:
 * Width:
 * BorderlandsGOTY.exe+81E1EC : FF 15 CE790F01  call qword ptr [BorderlandsGOTY.exe+1915BC0] -> ucrtbase.wtol
 * BorderlandsGOTY.exe+81E1F2 : 44 8B F8        mov r15d,eax
 * Height:
 * BorderlandsGOTY.exe+81E24E : FF 15 6C790F01  call qword ptr [BorderlandsGOTY.exe+1915BC0] -> ucrtbase.wtol
 * BorderlandsGOTY.exe+81E254 : 44 8B E0        mov r12d,eax
 *
 * The hooks where placed where the move instruction takes place and eax was overwritten with the
 * provided width and height parameters from the configuration file.
 *
 * Hooking for `patternFind2`:
 * Going beyond 21:9 is problematic as it introduces some artifacting to the left of the screen
 * which is a copy of what is on the right side of the screen. I can probably say this is some
 * mathematical oversight as the devs couldn't forsee in 2009 that people would be trying to play
 * this game in resolutions like 32:9, so whatever is happening code side is mostly a math error
 * that stems from being at 32:9 and beyond. I don't exactly understand why hooking here and
 * slightly changing the value in rax register would fix the issue, but it works and the artifacting
 * is gone and there are no visible anomalies by doing this.
 *
 * This fix would not work right off the bat on game boot up. The user would need to apply some
 * random resolution in game in order to get the target resolution injected in, this is inconvenient
 * and annoying to do every time. After digging around the code to find where windows where being
 * created and such I did manage to figure out certain things but nothing concrete on how the window
 * was having its resolution applied. Initially the window would be brought up in the desktop
 * resolution but would then later be resized to the target resolution provided in the launcher.
 * After some trial and error mixed with experimentation it seems that the game's binary .data
 * section allocates space for width and height, 4B each. So via cheat engine you can scan for
 * the width and height parameters, and you will get some hits in binary. There is more than one
 * but through testing I found that only 1 actually had any effect. So I went with that one at
 * BorderlandsGOTY.exe+25E50A0 and 25E50A4, width and height respectively. Notice they are 4B
 * apart.
 *
 * @return void
 */
void resolutionFix() {
    const char* patternFind0  = "44 8B ?? 41 8D ?? ?? 48 8B ?? ?? ?? FF 15 ?? ?? ?? ??";
    uintptr_t hookOffset0 = 0;
    const char* patternFind1  = "FF 15 ?? ?? ?? ?? 44 8B ?? 45 8B ??";
    uintptr_t hookOffset1 = 6;
    const char* patternFind2  = "CC    8B 81 A0 00 00 00    C3    CC";
    uintptr_t hookOffset2 = 7;
    std::vector<uintptr_t> resAddrPatch  = {
        (uintptr_t)baseModule + 0x25E50A0,
        (uintptr_t)baseModule + 0x25E5730,
        (uintptr_t)baseModule + 0x25E5C68,
        (uintptr_t)baseModule + 0x25E61A0,
        (uintptr_t)baseModule + 0x25E66D8,
        (uintptr_t)baseModule + 0x25E6974,
        (uintptr_t)baseModule + 0x25E6C10,
    };

    LOG("Desktop resolution: {}x{}",
        yml.resolution.width, yml.resolution.height
    );
    LOG("Aspect Ratio: {}:{} {}",
        yml.resolution.width / std::gcd(yml.resolution.width, yml.resolution.height),
        yml.resolution.height / std::gcd(yml.resolution.width, yml.resolution.height),
        yml.resolution.aspectRatio
    );

    bool enable = yml.masterEnable;
    LOG("Fix {}", enable ? "Enabled" : "Disabled");
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind0, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind0, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset0;
            uintptr_t hookRelAddr = relAddr + hookOffset0;
            static SafetyHookMid fovMidHook{};
            fovMidHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    ctx.rax = yml.resolution.width;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset0, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind0);
        }
    }
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind1, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind1, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset1;
            uintptr_t hookRelAddr = relAddr + hookOffset1;
            static SafetyHookMid fovMidHook{};
            fovMidHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    ctx.rax = yml.resolution.height;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset1, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind1);
        }
    }
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind2, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind2, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset2;
            uintptr_t hookRelAddr = relAddr + hookOffset2;
            static SafetyHookMid fovMidHook{};
            fovMidHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    ctx.rax = yml.resolution.height + 0x1;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset2, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind2);
        }
    }
    if (enable) {
        std::string widthString = Utils::bytesToString((void*)&yml.resolution.width, sizeof(yml.resolution.width));
        std::string heightString = Utils::bytesToString((void*)&yml.resolution.height, sizeof(yml.resolution.height));
        std::string resString = widthString + ' ' + heightString;
        for (size_t i = 0; i < resAddrPatch.size(); i++) {
            Utils::patch(resAddrPatch[i], resString.c_str());
            LOG("Patched '{}' @ 0x{:x}", resString, resAddrPatch[i]);
        }
    }
}

/**
 * @brief Applies a field of view (FOV) fix by hooking a specific pattern in memory.
 *
 * This function performs the following tasks:
 * 1. Checks if the FOV fix is enabled based on the configuration.
 * 2. Searches for a specific memory pattern in the base module.
 * 3. Hooks the identified pattern to modify the FOV value.
 *
 * @details
 * The function uses a pattern scan to find a specific byte sequence in the memory of the base module.
 * If the pattern is found, a hook is created from the found pattern address. The hook modifies the FOV
 * value by adjusting it according to the aspect ratio and desired FOV specified in the configuration.
 *
 * The hook function calculates the new FOV value using trigonometric functions based on the current
 * aspect ratio and the desired FOV, then applies this new value to the appropriate register.
 * NOTE: The FOV value specified in the configuration file will not be the actual FOV value that is applied,
 * unless the aspect ratio is 16:9. Because of the game's use of vert- scaling the FOV needs to be adjusted
 * so that the image emulates the FOV of 16:9.
 *
 * The memory for the FOV setting is dynamically allocated in the game's .bss section and is not present
 * in the binary. Hence it cannot be patched with a byte write, and needs a hook so that it may be changed
 * while in a register.
 *
 * FOV is stored multiple times across various addresses. When moving the slider in game, the FOV value,
 * in hex form, manipulates 4 32-bit memory locations. And the FOV is not actually set until you exit
 * out of the menu back into the game.
 *
 * Trying to write some of the locations you will quickly find out that there is code that constantly
 * rewrites the FOV value with some master value. Through some trial and error and tracing what
 * instructions access and write the locations we stumble some code that seems to be the master FOV
 * controller.
 * Relevent Code:
 * BorderlandsGOTY.exe+143AD0F : F3 0F11 83 480F0000  movss [rbx+00000F48],xmm0
 * BorderlandsGOTY.exe+143AD17 : 8B 88 D8030000       mov   ecx,[rax+000003D8]
 * BorderlandsGOTY.exe+143AD1D : 89 8B 4C0F0000       mov   [rbx+00000F4C],ecx
 * BorderlandsGOTY.exe+143AD23 : 48 83 C4 20          add   rsp,20
 * BorderlandsGOTY.exe+143AD27 : 5B                   pop   rbx
 * BorderlandsGOTY.exe+143AD28 : C3                   ret
 *
 * The register xmm0 contains the master value, so if we hook right there and change the value, it will
 * fix the FOV throughout the whole game. The FOV calculations in this game are not only complex, but
 * also happen indiscriminently in different parts of the game depending on the context. Given this
 * information, the fix needs to assume certain things firstly the user has maxed out the in game FOV.
 * Why maxed out? Simply this is the max FOV the game allows before the camera starts to break with the
 * finite impulse response oscillation when loading into the game for the first time for example. Anyhow
 * we can mimic by doing (currentFov / 120.0f) and multiplying user specified FOV in the config file,
 * and we have something close to what the actual in game FOV would be, bells and whistles attached.
 *
 * TODO: The superior solution would be to find where the game sets vert- scaling and force it to do hor+
 * scaling instead.
 *
 * @return void
 */
void fovFix() {
    const char* patternFind  = "F3 0F 11 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 48 83 ?? ?? 5B C3";
    uintptr_t hookOffset = 0;

    bool enable = yml.masterEnable & yml.fix.fov.enable;
    LOG("Fix {}", enable ? "Enabled" : "Disabled");
    if (enable) { // Master FOV controller
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset;
            uintptr_t hookRelAddr = relAddr + hookOffset;
            static SafetyHookMid fovMidHook{};
            fovMidHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    float pi = std::numbers::pi_v<float>;
                    float newFov = atanf((tanf(yml.fix.fov.value * pi / 360.0f) / nativeAspectRatio) * yml.resolution.aspectRatio) * 360.0f / pi;
                    // Scale FOV based on current FOV stored and using ingame FOV of 120.0f
                    newFov *= (ctx.xmm0.f32[0] / 120.0f);
                    ctx.xmm0.f32[0] = newFov;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind);
        }
    }
}

/**
 * @brief Main function that initializes and applies various fixes.
 *
 * This function serves as the entry point for the DLL. It performs the following tasks:
 * 1. Initializes the logging system.
 * 2. Reads the configuration from a YAML file.
 * 3. Sleeps for 5 second to give the game time to load up, fixes won't work otherwise,
 *      and patched resolution will be overwritten by the game.
 * 3. Applies a resolution fix.
 * 5. Applies a field of view (FOV) fix.
 *
 * @param lpParameter Unused parameter.
 * @return Always returns TRUE to indicate successful execution.
 */
DWORD __stdcall Main(void* lpParameter) {
    logInit();
    readYml();
    Sleep(5000); // TODO: Find a better solution
    resolutionFix();
    fovFix();
    return true;
}

/**
 * @brief Entry point for a DLL, called by the system when the DLL is loaded or unloaded.
 *
 * This function handles various events related to the DLL's lifetime and performs actions
 * based on the reason for the call. Specifically, it creates a new thread when the DLL is
 * attached to a process.
 *
 * @details
 * The `DllMain` function is called by the system when the DLL is loaded or unloaded. It handles
 * different reasons for the call specified by `ul_reason_for_call`. In this implementation:
 *
 * - **DLL_PROCESS_ATTACH**: When the DLL is loaded into the address space of a process, it
 *   creates a new thread to run the `Main` function. The thread priority is set to the highest,
 *   and the thread handle is closed after creation.
 *
 * - **DLL_THREAD_ATTACH**: Called when a new thread is created in the process. No action is taken
 *   in this implementation.
 *
 * - **DLL_THREAD_DETACH**: Called when a thread exits cleanly. No action is taken in this implementation.
 *
 * - **DLL_PROCESS_DETACH**: Called when the DLL is unloaded from the address space of a process.
 *   No action is taken in this implementation.
 *
 * @param hModule Handle to the DLL module. This parameter is used to identify the DLL.
 * @param ul_reason_for_call Indicates the reason for the call (e.g., process attach, thread attach).
 * @param lpReserved Reserved for future use. This parameter is typically NULL.
 * @return BOOL Always returns TRUE to indicate successful execution.
 */
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    HANDLE mainHandle;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        LOG("DLL_PROCESS_ATTACH");
        mainHandle = CreateThread(NULL, 0, Main, 0, NULL, 0);
        if (mainHandle)
        {
            SetThreadPriority(mainHandle, THREAD_PRIORITY_HIGHEST);
            CloseHandle(mainHandle);
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

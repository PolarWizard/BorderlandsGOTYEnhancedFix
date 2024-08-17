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

// 3rd party includes
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "yaml-cpp/yaml.h"
#include "safetyhook.hpp"

// Local includes
#include "utils.hpp"

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

HMODULE baseModule = GetModuleHandle(NULL);
YAML::Node config = YAML::LoadFile("BorderlandsGOTYEnhancedFix.yml");
yml_t yml;

float nativeAspectRatio = 16.0f / 9.0f;

void logInit() {
    // spdlog initialisation
    auto logger = spdlog::basic_logger_mt("BorderlandsGOTYEnhanced", "BorderlandsGOTYEnhancedFix.log");
    spdlog::set_default_logger(logger);
    spdlog::flush_on(spdlog::level::debug);

    // Get game name and exe path
    WCHAR exePath[_MAX_PATH] = { 0 };
    GetModuleFileNameW(baseModule, exePath, MAX_PATH);
    std::filesystem::path exeFilePath = exePath;
    std::string exeName = exeFilePath.filename().string();

    // Log module details
    LOG("-------------------------------------");
    LOG("Module Name: {:s}", exeName.c_str());
    LOG("Module Path: {:s}", exeFilePath.string().c_str());
    LOG("Module Addr: 0x{:x}", (uintptr_t)baseModule);
}

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

void resolutionFix() {
    const char* patternFind0  = "44 8B ?? 41 8D ?? ?? 48 8B ?? ?? ?? FF 15 ?? ?? ?? ??";
    uintptr_t hookOffset0 = 0;
    const char* patternFind1  = "FF 15 ?? ?? ?? ?? 44 8B ?? 45 8B ??";
    uintptr_t hookOffset1 = 6;
    uint64_t resWidthAddrPatch  = (uintptr_t)baseModule + 0x25E50A0;
    uint64_t resHeightAddrPatch = (uintptr_t)baseModule + 0x25E50A4;

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
        std::string widthString = Utils::bytesToString((void*)&yml.resolution.width, sizeof(yml.resolution.width));
        std::string heightString = Utils::bytesToString((void*)&yml.resolution.height, sizeof(yml.resolution.height));

        Utils::patch(resWidthAddrPatch, widthString.c_str());
        LOG("Patched '{}' @ 0x{:x}", widthString, resWidthAddrPatch);
        Utils::patch(resHeightAddrPatch, heightString.c_str());
        LOG("Patched '{}' @ 0x{:x}", heightString, resHeightAddrPatch);
    }
}

void fovFix() {
    const char* patternFind  = "F3 0F 11 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 48 83 ?? ?? 5B C3";
    uintptr_t hookOffset = 0;
    const char* patternPatch = "";
    bool enableHook1 = true;
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

DWORD __stdcall Main(void*) {
    logInit();
    readYml();
    Sleep(1000);
    resolutionFix();
    fovFix();
    return true;
}

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

# Borderlands GOTY Enhanced Fix
Adds support for ultrawide resolutions and additional features.

***This project is designed exclusively for Windows due to its reliance on Windows-specific APIs. The build process requires the use of PowerShell.***

## Features
- Adds support for ultrawide resolutions
- Corrects FOV

## Build and Install
### Using CMake
1. Build and install:
```ps1
git clone --recurse-submodules https://github.com/PolarWizard/BorderlandsGOTYEnhancedFix.git
cd BorderlandsGOTYEnhancedFix; mkdir build; cd build
# For a general build:
cmake ..
cmake --build .
cmake --install .

# For a release build:
# Assumes Ninja and GCC are installed.
cmake -GNinja .. -DGCC_RELEASE=ON
cmake --build . --config Release
cmake --install .
```
```
`cmake ..` will attempt to find the game folder in `C:/Program Files (x86)/Steam/steamapps/common/`. If the game folder cannot be found rerun the command providing the path to the game folder:<br>`cmake .. -DGAME_FOLDER="<FULL-PATH-TO-GAME-FOLDER>"`

2. Download [winmm.dll](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) x64 version
3. Extract to `BorderlandsGOTYEnhanced/Binaries/Win64`

#### Why does release build use GCC?
MSVC and Clang in MSVC mode default to linking against the Microsoft C++ runtime libraries (`vcruntime*.dll` and `msvcp*.dll` when using Visual Studio 2022), which can create dependency issues when distributing the compiled binaries. By using GCC it allows you to statically link `libgcc` and `libstdc++`, which means the runtime components are included directly in your executable. This makes things easier as you are no longer dependent on Microsoft external DLLs, which may or may not be present on the target system, making the application more portable and accessible for users.

### Using Release
1. Download and follow instructions in [latest release](https://github.com/PolarWizard/BorderlandsGOTYEnhancedFix/releases)

## Configuration
- Adjust settings in `BorderlandsGOTYEnhanced/Binaries/Win64/scripts/BorderlandsGOTYEnhancedFix.yml`

## Screenshots
![Demo](images/BorderlandsGOTYEnhancedFix_1.gif)

## Known Issues
- FOV fix removes gameplay dynamics like the widening camera effect during running and the initial camera bounce when loading in
- Wierd graphics artifacting on left side of screen if resolution exceeds 21:9
- HUD is stretched above when resolution exceeds 16:9
- Game will stretch image to fill screen if provided resolution is smaller than desktop resolution in fullscreen mode - **WILL NOT BE FIXED**
- Changing resolution and fullscreen settings ingame will break fix - **WILL NOT BE FIXED**

## License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## External Tools
- [safetyhook](https://github.com/cursey/safetyhook)
- [spdlog](https://github.com/gabime/spdlog)
- [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
- [yaml-cpp](https://github.com/jbeder/yaml-cpp)
- [zydis](https://github.com/zyantific/zydis)

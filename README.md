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
cmake ..
cmake --build .
cmake --install .
```
`cmake ..` will attempt to find the game folder in `C:/Program Files (x86)/Steam/steamapps/common/`. If the game folder cannot be found rerun the command providing the path to the game folder:<br>`cmake .. -DGAME_FOLDER="<FULL-PATH-TO-GAME-FOLDER>"`

2. Download [winmm.dll](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) x64 version
3. Extract to `BorderlandsGOTYEnhanced/Binaries/Win64`

### Using Release Candidate
1. Download and follow instructions in [latest release](https://github.com/PolarWizard/BorderlandsGOTYEnhancedFix/releases)

## Configuration
- Adjust settings in `BorderlandsGOTYEnhanced/Binaries/Win64/scripts/BorderlandsGOTYEnhancedFix.yml`

## Screenshots
![Demo](images/BorderlandsGOTYEnhancedFix_1.gif)

## Known Issues
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

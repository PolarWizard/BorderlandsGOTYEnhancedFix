# MIT License
#
# Copyright (c) 2024 Dominik Protasewicz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.28)

# Options
option(GCC_RELEASE "Make GCC Release" OFF)

# Variables
set(PROJECT_NAME BorderlandsGOTYEnhancedFix)
set(DEFAULT_GAME_FOLDER "C:/Program Files (x86)/Steam/steamapps/common/BorderlandsGOTYEnhanced")
set(GAME_FOLDER "${DEFAULT_GAME_FOLDER}" CACHE STRING "User specified path to game folder")
if (EXISTS "${GAME_FOLDER}/Binaries/Win64/BorderlandsGOTY.exe")
    message(STATUS "Game folder: ${GAME_FOLDER}")
else()
    message(FATAL_ERROR "Bad game folder provided: ${GAME_FOLDER}")
endif()

if (GCC_RELEASE)
    message(STATUS "Configured for GCC Release")
    set(CMAKE_BUILD_TYPE Release)
    set(CMAKE_STATIC_LIBRARY_PREFIX_CXX "")
    set(CMAKE_C_COMPILER gcc)
    set(CMAKE_CXX_COMPILER g++)
    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED True)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -static-libgcc -static-libstdc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -static-libgcc -static-libstdc++")
endif()

# Set the project name and version
project(${PROJECT_NAME} VERSION 1.0)
set(CMAKE_SHARED_LIBRARY_PREFIX "")

# Define the common output directory
set(OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Configure debug and release directories separately
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${OUTPUT_DIRECTORY}/Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${OUTPUT_DIRECTORY}/Release)

#Get all src files
file(GLOB_RECURSE SOURCE src/*.cpp)

# Add DLL
add_library(${PROJECT_NAME} SHARED ${SOURCE})

# Add directory and build
add_subdirectory(yaml-cpp EXCLUDE_FROM_ALL)
add_subdirectory(zydis EXCLUDE_FROM_ALL)
add_subdirectory(safetyhook EXCLUDE_FROM_ALL)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    inc
    spdlog/include
    yaml-cpp/include
    safetyhook/include
)

# Include libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    Zydis
    yaml-cpp
    safetyhook
)

install(CODE "
    execute_process(
        COMMAND
            powershell.exe
                -ExecutionPolicy Bypass
                -File \"${CMAKE_SOURCE_DIR}/install.ps1\" \"${GAME_FOLDER}\"
    )
")

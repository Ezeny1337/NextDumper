cmake_minimum_required(VERSION 3.22)

project(NextDumper VERSION 0.1.0 LANGUAGES CXX)

if(NOT ANDROID)
    message(FATAL_ERROR "NextDumper currently supports Android only")
endif()

if(NOT CMAKE_ANDROID_ARCH_ABI MATCHES "^(arm64-v8a|armeabi-v7a)$")
    message(FATAL_ERROR "NextDumper currently supports arm64-v8a and armeabi-v7a only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(NEXTDUMPER_PRODUCER_COMMIT "unknown")
set(NEXTDUMPER_PRODUCER_WORKTREE "unknown")
find_package(Git QUIET)
if(Git_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --verify HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        RESULT_VARIABLE NEXTDUMPER_GIT_RESULT
        OUTPUT_VARIABLE NEXTDUMPER_GIT_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(NEXTDUMPER_GIT_RESULT STREQUAL "0" AND NEXTDUMPER_GIT_COMMIT MATCHES "^[0-9a-fA-F]+$")
        set(NEXTDUMPER_PRODUCER_COMMIT "${NEXTDUMPER_GIT_COMMIT}")
        execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=normal
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            RESULT_VARIABLE NEXTDUMPER_GIT_STATUS_RESULT
            OUTPUT_VARIABLE NEXTDUMPER_GIT_STATUS OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
        if(NEXTDUMPER_GIT_STATUS_RESULT STREQUAL "0")
            if(NEXTDUMPER_GIT_STATUS STREQUAL "")
                set(NEXTDUMPER_PRODUCER_WORKTREE "clean")
            else()
                set(NEXTDUMPER_PRODUCER_WORKTREE "dirty")
            endif()
        else()
            message(WARNING "Git worktree status is unavailable; producer worktree remains unknown")
        endif()
    else()
        message(WARNING "Git revision is unavailable; producer identity remains unknown")
    endif()
else()
    message(WARNING "Git is unavailable; producer identity remains unknown")
endif()
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated/nextdumper")
configure_file(cmake/BuildInfo.hpp.in generated/nextdumper/BuildInfo.hpp @ONLY)

option(NEXTDUMPER_ENABLE_THINLTO "Enable ThinLTO for native targets" ON)
option(NEXTDUMPER_OPTIMIZE_FOR_SIZE "Use Clang size optimization for native targets" OFF)
option(NEXTDUMPER_FORCE_NDEBUG "Define NDEBUG for all native targets" OFF)
option(NEXTDUMPER_DISABLE_NDEBUG "Undefine NDEBUG for all native targets" OFF)

if(NEXTDUMPER_FORCE_NDEBUG AND NEXTDUMPER_DISABLE_NDEBUG)
    message(FATAL_ERROR "NEXTDUMPER_FORCE_NDEBUG and NEXTDUMPER_DISABLE_NDEBUG are mutually exclusive")
endif()

set(KITTY_MEMORY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/KittyMemoryEx")
file(GLOB KITTY_MEMORY_SOURCES CONFIGURE_DEPENDS "${KITTY_MEMORY_DIR}/*.cpp")

add_library(kitty_memory_ex STATIC ${KITTY_MEMORY_SOURCES})
target_include_directories(kitty_memory_ex SYSTEM PUBLIC "${KITTY_MEMORY_DIR}")
target_compile_definitions(kitty_memory_ex PUBLIC kNO_KEYSTONE)
target_compile_options(kitty_memory_ex PRIVATE -fexceptions)
target_link_libraries(kitty_memory_ex PUBLIC log)

file(GLOB UE_ANALYZER_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer/Architecture/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer/UEAnalyzer/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer/UEAnalyzer/Analysis/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer/UEAnalyzer/Core/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer/UEAnalyzer/Strategies/*.cpp"
)

add_library(ue_analyzer STATIC ${UE_ANALYZER_SOURCES})
target_include_directories(ue_analyzer PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer")
target_include_directories(ue_analyzer SYSTEM PUBLIC "${KITTY_MEMORY_DIR}")
target_compile_features(ue_analyzer PUBLIC cxx_std_20)
target_compile_options(ue_analyzer PRIVATE -Wall -Wextra -Wno-unused-parameter -fexceptions)
target_link_libraries(ue_analyzer PUBLIC kitty_memory_ex)

add_library(nextdumper_core STATIC
    src/app/CompatibilityDiagnosis.cpp
    src/app/RuntimeSession.cpp
    src/analyzer/AnalyzerMemoryAdapter.cpp
    src/binding/BindingBuilder.cpp
    src/binding/CommonObjectCollector.cpp
    src/binding/GlobalLocator.cpp
    src/binding/LayoutDiscovery.cpp
    src/binding/LayoutProbes.cpp
    src/binding/RuntimeBinding.cpp
    src/compat/GameProfiles.cpp
    src/generation/ArtifactWriter.cpp
    src/generation/ArtifactMetadata.cpp
    src/generation/GenerationReport.cpp
    src/generation/SdkEmitter.cpp
    src/generation/CppTypeResolver.cpp
    src/generation/JsonExport.cpp
    src/memory/CaptureMemorySource.cpp
    src/memory/ProcessInfo.cpp
    src/memory/RemoteMemorySource.cpp
    src/module/ModuleCatalog.cpp
    src/module/ModuleImage.cpp
    src/module/ElfSymbols.cpp
    src/module/ElfSymbolQuery.cpp
    src/reflection/ReflectionReader.cpp
    src/reflection/ReflectionEvidenceLog.cpp
    src/reflection/RuntimeInspector.cpp
    src/reflection/RuntimeFieldPlanner.cpp
    src/reflection/RuntimeValueReader.cpp
    src/reflection/ReflectionLayout.cpp
    src/ue/ContainerLayout.cpp
    src/ue/ContainerReader.cpp
    src/ue/StorageLayout.cpp
    src/ue/EngineSchema.cpp
    src/ue/EngineVersion.cpp
    src/ue/FunctionSemantics.cpp
    src/ue/NameStoreReader.cpp
    src/ue/ObjectModelReader.cpp
    src/ue/ObjectStoreReader.cpp
    src/ue/SchemaCatalog.cpp
    src/ue/SchemaEnum.cpp
    src/ue/SchemaField.cpp
    src/ue/SchemaFunction.cpp
    src/ue/SchemaObject.cpp
    src/ue/SchemaProperty.cpp
    src/ue/SchemaSubtypes.cpp
    src/ue/SchemaResolver.cpp
    src/ue/SchemaStruct.cpp
    src/ue/SchemaSelection.cpp
)

target_include_directories(nextdumper_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
target_include_directories(nextdumper_core SYSTEM PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer"
)

target_compile_options(nextdumper_core PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -fexceptions
)
target_link_libraries(nextdumper_core PUBLIC kitty_memory_ex ue_analyzer)

add_executable(NextDumper src/app/main.cpp)
target_link_libraries(NextDumper PRIVATE nextdumper_core)
target_compile_options(NextDumper PRIVATE -Wall -Wextra -Wpedantic -Werror)

set(NEXTDUMPER_NATIVE_TARGETS kitty_memory_ex ue_analyzer nextdumper_core NextDumper)
foreach(target IN LISTS NEXTDUMPER_NATIVE_TARGETS)
    target_compile_options(${target} PRIVATE
        -ffunction-sections
        -fdata-sections
    )
    if(NEXTDUMPER_ENABLE_THINLTO)
        target_compile_options(${target} PRIVATE -flto=thin)
    endif()
    if(NEXTDUMPER_OPTIMIZE_FOR_SIZE)
        target_compile_options(${target} PRIVATE -Oz)
    endif()
    if(NEXTDUMPER_FORCE_NDEBUG)
        target_compile_options(${target} PRIVATE -DNDEBUG)
    elseif(NEXTDUMPER_DISABLE_NDEBUG)
        target_compile_options(${target} PRIVATE -UNDEBUG)
    endif()
endforeach()

if(NEXTDUMPER_ENABLE_THINLTO)
    target_link_options(NextDumper PRIVATE -flto=thin)
endif()

# Android's lld removes unused function/data sections from the final executable.
target_link_options(NextDumper PRIVATE -Wl,--gc-sections)

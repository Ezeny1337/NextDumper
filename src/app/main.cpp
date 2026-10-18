#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <exception>

#include "nextdumper/app/RuntimeSession.hpp"

namespace
{
    void PrintUsage(const char *program)
    {
        std::fprintf(stderr, "Usage: %s -o <output-dir> -p <package-name> [options]\n", program);
        std::fprintf(stderr, "\nRequired arguments:\n");
        std::fprintf(stderr, "  -o, --output <dir>        Output directory for generated SDK\n");
        std::fprintf(stderr, "  -p, --package <name>      Target package name (e.g., com.example.app)\n");
        std::fprintf(stderr, "\nOptional arguments:\n");
        std::fprintf(stderr, "      --memory-log          Write memory performance JSONL (disabled by default)\n");
        std::fprintf(stderr, "  -h, --help                Show this help message\n");
        std::fprintf(stderr, "\nExample:\n");
        std::fprintf(stderr, "  %s -o ./output -p com.YS.Nicecity\n", program);
    }
} // namespace

int main(int argc, char **argv)
try
{
    nextdumper::app::RuntimeSessionConfig config;

    bool hasOutput = false;
    bool hasPackage = false;

    for (int index = 1; index < argc; ++index)
    {
        const std::string arg = argv[index];

        if (arg == "-h" || arg == "--help")
        {
            PrintUsage(argv[0]);
            return 0;
        }

        if (arg == "--memory-log")
        {
            config.enableMemoryLog = true;
            continue;
        }

        if (arg == "-o" || arg == "--output")
        {
            if (++index >= argc)
            {
                std::fprintf(stderr, "Error: %s requires an argument\n", arg.c_str());
                PrintUsage(argv[0]);
                return 2;
            }
            config.outputRoot = argv[index];
            hasOutput = true;
            continue;
        }

        if (arg == "-p" || arg == "--package")
        {
            if (++index >= argc)
            {
                std::fprintf(stderr, "Error: %s requires an argument\n", arg.c_str());
                PrintUsage(argv[0]);
                return 2;
            }
            config.packageName = argv[index];
            hasPackage = true;
            continue;
        }

        std::fprintf(stderr, "Error: Unknown argument: %s\n", arg.c_str());
        PrintUsage(argv[0]);
        return 2;
    }

    if (!hasOutput || !hasPackage)
    {
        std::fprintf(stderr, "Error: Missing required arguments\n\n");
        PrintUsage(argv[0]);
        return 2;
    }

    nextdumper::app::RuntimeSession session(std::move(config));
    const auto status = session.Run();

    std::printf("\n=== Session Summary ===\n");
    std::printf("Status: %d\n", static_cast<int>(status));

    if (!session.LogPath().empty())
        std::printf("Log: %s\n", session.LogPath().c_str());
    if (!session.MemoryPerformancePath().empty())
        std::printf("Memory performance: %s\n", session.MemoryPerformancePath().c_str());
    if (!session.DiagnosisPath().empty())
        std::printf("Diagnosis: %s\n", session.DiagnosisPath().c_str());

    if (!session.Failures().empty())
    {
        std::printf("\nFailures:\n");
        for (const std::string &failure : session.Failures())
            std::printf("  - %s\n", failure.c_str());
    }

    if (!session.Artifacts().outputPath.empty())
        std::printf("\nOutput: %s\n", session.Artifacts().outputPath.string().c_str());

    if (status == nextdumper::app::RuntimeSessionStatus::ReflectionReady)
        return 0;
    if (status == nextdumper::app::RuntimeSessionStatus::ReflectionPartial ||
        status == nextdumper::app::RuntimeSessionStatus::ArtifactPartial)
        return 3;
    return 1;
}
catch (const std::exception &error)
{
    std::fprintf(stderr, "Fatal error: %s\n", error.what());
    return 1;
}
catch (...)
{
    std::fprintf(stderr, "Fatal error: unknown exception\n");
    return 1;
}

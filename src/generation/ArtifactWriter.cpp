#include "nextdumper/generation/ArtifactWriter.hpp"
#include "ArtifactMetadata.hpp"
#include "SdkEmitter.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <utility>

namespace nextdumper::generation
{
    namespace
    {
        struct TemporaryDirectory
        {
            std::filesystem::path path;
            bool committed = false;
            ~TemporaryDirectory()
            {
                try
                {
                    if (!committed && !path.empty())
                    {
                        std::error_code error;
                        std::filesystem::remove_all(path, error);
                        if (error)
                            std::fprintf(stderr, "Temporary artifact cleanup failed: %s\n", error.message().c_str());
                    }
                }
                catch (...)
                {
                    std::fprintf(stderr, "Temporary artifact cleanup could not complete\n");
                }
            }
        };
    } // namespace

    ArtifactWriter::ArtifactWriter(const RuntimeContext &context,
                                   const ReflectionIR &reflection,
                                   std::filesystem::path outputRoot,
                                   std::string packageName,
                                   ArtifactProvenance provenance,
                                   std::function<void(const std::string &)> diagnostic)
        : context_(context), reflection_(reflection), outputRoot_(std::move(outputRoot)), packageName_(std::move(packageName)),
          provenance_(std::move(provenance)), diagnostic_(std::move(diagnostic))
    {
    }

    ArtifactResult ArtifactWriter::Write() const
    {
        ArtifactResult result;
        if (reflection_.status == ParseStatus::Failed)
        {
            result.error = "reflection input is failed";
            return result;
        }
        if (outputRoot_.empty() || packageName_.empty())
        {
            result.error = "output root and package name are required";
            return result;
        }
        if ((context_.Module().pointerWidth != 4 && context_.Module().pointerWidth != 8) ||
            (context_.Schema().fname.size != 4 && context_.Schema().fname.size != 8 && context_.Schema().fname.size != 12))
        {
            result.error = "target pointer width or FName size is invalid for SDK description generation";
            return result;
        }
        if (std::any_of(reflection_.types.begin(), reflection_.types.end(), [](const ir::TypeIR &type)
                        { return type.size < 0; }))
        {
            result.error = "negative reflected type size is invalid for SDK description generation";
            return result;
        }

        std::error_code error;
        std::filesystem::create_directories(outputRoot_, error);
        if (error)
        {
            result.error = "output root creation failed";
            return result;
        }
        const std::string packageStem = SanitizeIdentifier(packageName_, "Package");
        detail::GenerationReport report;
        const detail::SdkEmitter emitter(context_.Module(), context_.Schema(), reflection_);
        report.diagnostic = diagnostic_;
        const CppSymbols symbols = BuildCppSymbols(reflection_);
        TemporaryDirectory transaction;
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        for (int attempt = 0; attempt < 16; ++attempt)
        {
            const auto candidate = outputRoot_ / ("." + packageStem + ".tmp." + std::to_string(stamp) + "." + std::to_string(attempt));
            if (std::filesystem::create_directory(candidate, error))
            {
                transaction.path = candidate;
                break;
            }
            if (error == std::errc::file_exists)
                error.clear();
            else if (error)
                break;
        }
        if (transaction.path.empty())
        {
            result.error = "temporary output directory creation failed";
            return result;
        }
        const auto writeFile = [&](const char *name, const auto &emit)
        {
            std::array<char, 64 * 1024> buffer;
            std::ofstream stream;
            stream.rdbuf()->pubsetbuf(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            stream.open(transaction.path / name, std::ios::binary | std::ios::trunc);
            if (!stream.is_open())
            {
                result.error = "output file open failed: " + std::string(name);
                return false;
            }
            emit(stream);
            stream.flush();
            if (!stream.good())
            {
                result.error = "output file write or flush failed: " + std::string(name);
                return false;
            }
            stream.close();
            if (stream.fail())
            {
                result.error = "output file close failed: " + std::string(name);
                return false;
            }
            ++result.filesWritten;
            return true;
        };
        if (!writeFile("BasicTypes.hpp", [&](std::ostream &stream)
                       { emitter.BasicTypes(stream, symbols); }) ||
            !writeFile("EngineLayouts.hpp", [&](std::ostream &stream)
                       { emitter.EngineLayouts(stream); }) ||
            !writeFile("Types.hpp", [&](std::ostream &stream)
                       { emitter.Types(stream, symbols, report); }) ||
            !writeFile("Enums.hpp", [&](std::ostream &stream)
                       { emitter.Enums(stream, symbols); }) ||
            !writeFile("Functions.hpp", [&](std::ostream &stream)
                       { emitter.Functions(stream, symbols, report); }) ||
            !writeFile("reflection.json", [&](std::ostream &stream)
                       { detail::ReflectionJson(stream, context_, reflection_, report, symbols); }))
            return result;
        const ParseStatus status = reflection_.status == ParseStatus::Partial || report.Status() == ParseStatus::Partial
                                       ? ParseStatus::Partial
                                       : ParseStatus::Complete;
        result.reflectionStatus = reflection_.status;
        result.sdkStatus = report.Status();
        result.opaqueFields = report.opaqueFields;
        result.omittedFields = report.omittedFields;
        result.layoutWarnings = report.layoutWarnings;
        report.LogOmitted();
        result.generationDiagnostics = report.Summaries();
        const std::string artifactStem = packageStem + (status == ParseStatus::Partial ? ".partial" : "") +
                                         (provenance_.runTimestamp.empty() ? std::string{} : "_" + provenance_.runTimestamp);
        const std::filesystem::path finalPath = outputRoot_ / artifactStem;
        if (std::filesystem::exists(finalPath, error))
        {
            // 目标目录已有相同 SDK 时先整体删除，随后由临时目录 rename 重建
            std::filesystem::remove_all(finalPath, error);
            if (error)
            {
                result.error = "existing output directory removal failed: " + error.message();
                return result;
            }
        }
        if (error)
        {
            result.error = "output directory check failed: " + error.message();
            return result;
        }
        if (!writeFile("manifest.json", [&](std::ostream &stream)
                       { detail::ManifestJson(stream, context_, reflection_, packageName_, provenance_, report, status); }) ||
            !writeFile("diagnostics.json", [&](std::ostream &stream)
                       { detail::DiagnosticsJson(stream, context_, reflection_, report, status); }) ||
            !writeFile("runtime.json", [&](std::ostream &stream)
                       { detail::RuntimeJson(stream, context_); }))
            return result;
        std::filesystem::rename(transaction.path, finalPath, error);
        if (error)
        {
            result.error = "output directory commit failed";
            return result;
        }
        transaction.committed = true;
        result.outputPath = finalPath;
        result.status = status;
        return result;
    }
} // namespace nextdumper::generation

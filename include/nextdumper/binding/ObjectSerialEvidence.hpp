#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nextdumper::binding
{
    struct ObjectSerialDiscoveryLimits
    {
        static constexpr size_t kMaxWindows = 512;
        static constexpr size_t kMaxReferenceReads = 32768;
        static constexpr size_t kMaxOwnersPerClass = 16;
        static constexpr size_t kMaxTargetSamples = 64;
        static constexpr size_t kMaxItemBytes = 256;
        static constexpr size_t kMinDiscoveryTargets = 4;
        static constexpr size_t kMinValidatedTargets = 8;
        static constexpr size_t kMinOwners = 2;
        static constexpr size_t kMaxDiagnosticSamples = 12;
        static constexpr size_t kMaxRejectedDiagnosticSamples = 4;
    };

    struct ObjectSerialCandidate
    {
        int32_t offset = -1;
        size_t targets = 0;
        size_t distinctSerials = 0;
        size_t owners = 0;
    };

    struct ObjectSerialSample
    {
        uintptr_t owner = 0;
        uintptr_t reference = 0;
        uintptr_t target = 0;
        uintptr_t item = 0;
        int32_t targetIndex = -1;
        int32_t serial = 0;
        std::string status;
        std::string path;
        std::vector<int32_t> matchingOffsets;
        std::vector<uint8_t> itemBytes;
    };

    // 描述采集时的关联证据，不保证 GC 存活、原子快照或其他模块构建的布局
    struct ObjectSerialEvidence
    {
        std::string status = "not-analyzed";
        int32_t selectedOffset = -1;
        int32_t objectSlots = 0;
        size_t scannedSlots = 0;
        size_t referenceReads = 0;
        size_t nonNullReferences = 0;
        size_t stableTargets = 0;
        size_t validatedTargets = 0;
        int32_t itemBytes = 0;
        bool scanComplete = false;
        std::map<std::string, size_t> skipped;
        std::vector<ObjectSerialCandidate> candidates;
        std::vector<ObjectSerialSample> samples;
    };
} // namespace nextdumper::binding

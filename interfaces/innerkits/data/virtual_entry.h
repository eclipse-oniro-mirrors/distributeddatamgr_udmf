/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UDMF_VIRTUAL_ENTRY_H
#define UDMF_VIRTUAL_ENTRY_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS::UDMF {
// Internal persisted marker used to distinguish virtual file records from
// ordinary file URI records when the runtime provider is unavailable.
constexpr char VIRTUAL_ENTRY_FLAG[] = "ohos.udmf.virtualEntry";

enum class VirtualEntryType : uint8_t { FILE, DIRECTORY };

// Metadata used exclusively by the provider IPC. It is not a ValueType and
// therefore cannot enter UnifiedData TLV serialization.
struct VirtualEntry {
    std::string id;
    std::string name;
    VirtualEntryType type{ VirtualEntryType::FILE };
    int64_t modifyTime{ 0 };
    // A file must declare a non-negative size before it can be published.
    // -1 is only the unset construction state and directory sentinel.
    int64_t size{ -1 };
    std::vector<VirtualEntry> subItems;

    bool HasValidFileSizes(uint32_t depth = 0) const
    {
        constexpr uint32_t maxDepth = 64;
        if (depth > maxDepth) {
            return false;
        }
        if (type == VirtualEntryType::FILE) {
            return size >= 0;
        }
        if (type != VirtualEntryType::DIRECTORY) {
            return false;
        }
        for (const auto &child : subItems) {
            if (!child.HasValidFileSizes(depth + 1)) {
                return false;
            }
        }
        return true;
    }
};
} // namespace OHOS::UDMF

#endif // UDMF_VIRTUAL_ENTRY_H

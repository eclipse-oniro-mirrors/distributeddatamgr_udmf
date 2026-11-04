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

#ifndef UDMF_VIRTUAL_ENTRY_CAPI_H
#define UDMF_VIRTUAL_ENTRY_CAPI_H

#include <memory>
#include <mutex>

#include "udmf_capi_common.h"
#include "uds.h"
#include "virtual_entry.h"
#include "virtual_entry_provider.h"

namespace OHOS::UDMF {
class File;

class NdkVirtualEntryCallbacks final {
public:
    NdkVirtualEntryCallbacks(
        const OH_UDMF_VirtualFileCallbacks &callbacks, void *context, OH_UDMF_VirtualFileFinalize finalize);
    ~NdkVirtualEntryCallbacks();

    const OH_UDMF_VirtualFileCallbacks callbacks_;
    void *const context_;

private:
    const OH_UDMF_VirtualFileFinalize finalize_;
};

struct NdkVirtualEntryInfo {
    VirtualEntry entry;
    std::shared_ptr<NdkVirtualEntryCallbacks> callbacks;
};

sptr<IVirtualEntryProvider> CreateNdkVirtualEntryProvider(const std::shared_ptr<NdkVirtualEntryInfo> &info);
bool AttachNdkVirtualEntry(const std::shared_ptr<File> &file, const std::shared_ptr<NdkVirtualEntryInfo> &info);
} // namespace OHOS::UDMF

struct OH_UDMF_VirtualItem {
    const int64_t cid = NdkStructId::UDMF_VIRTUAL_ITEM_STRUCT_ID;
    OHOS::UDMF::VirtualEntry entry_;
    mutable std::mutex mutex;
};

struct OH_UDMF_VirtualFileInfo {
    const int64_t cid = NdkStructId::UDMF_VIRTUAL_FILE_INFO_STRUCT_ID;
    std::shared_ptr<OHOS::UDMF::NdkVirtualEntryInfo> info_;
};

#endif // UDMF_VIRTUAL_ENTRY_CAPI_H

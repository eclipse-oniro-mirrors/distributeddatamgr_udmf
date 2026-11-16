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

#ifndef UDMF_VIRTUAL_ENTRY_PARCEL_H
#define UDMF_VIRTUAL_ENTRY_PARCEL_H

#include "message_parcel.h"
#include "virtual_entry.h"
#include "visibility.h"

namespace OHOS::UDMF {
class API_EXPORT VirtualEntryParcel {
public:
    // A maximum-length 4096-node tree fits within this rounded, bounded budget.
    static constexpr uint32_t MAX_BYTES = 8 * 1024 * 1024;
    static bool Write(MessageParcel &parcel, const VirtualEntry &entry);
    static bool Read(MessageParcel &parcel, VirtualEntry &entry);

private:
    static constexpr uint32_t VERSION = 1;
    static constexpr uint32_t MAX_COUNT = 4096;
    static constexpr uint32_t MAX_DEPTH = 64;
    static constexpr size_t MAX_ID_BYTES = 1024;
    static constexpr size_t MAX_NAME_BYTES = 255;
    static bool WriteNode(Parcel &parcel, const VirtualEntry &entry, uint32_t &count, uint32_t depth);
    static bool ReadNode(Parcel &parcel, VirtualEntry &entry, uint32_t &count, uint32_t depth);
};
} // namespace OHOS::UDMF
#endif // UDMF_VIRTUAL_ENTRY_PARCEL_H

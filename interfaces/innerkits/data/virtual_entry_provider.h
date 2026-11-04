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

#ifndef UDMF_VIRTUAL_ENTRY_PROVIDER_H
#define UDMF_VIRTUAL_ENTRY_PROVIDER_H

#include <vector>

#include "iremote_broker.h"
#include "virtual_entry.h"

namespace OHOS::UDMF {
enum class VirtualEntryProviderCode : uint32_t { STAT = 0, READ, CANCEL, READ_ASYNC };

class IVirtualEntryProvider : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.UDMF.VirtualEntryProvider");
    virtual int32_t Stat(const std::string &id, VirtualEntry &entry) = 0;
    virtual int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) = 0;
    virtual int32_t Cancel(const std::vector<std::string> &ids) = 0;
};
} // namespace OHOS::UDMF

#endif // UDMF_VIRTUAL_ENTRY_PROVIDER_H

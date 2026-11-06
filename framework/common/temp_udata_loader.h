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

#ifndef UDMF_TEMP_UDATA_LOADER_H
#define UDMF_TEMP_UDATA_LOADER_H

#include "unified_data.h"

namespace OHOS {
namespace UDMF {

class TempUDataLoader {
public:
    TempUDataLoader() = delete;
    ~TempUDataLoader() = delete;

    static bool FileClose(std::FILE *file, bool status);
    static bool IsTempUData(const UnifiedData &data);
    static bool Decode(const UnifiedData &packed, UnifiedData &decoded);
};

} // namespace UDMF
} // namespace OHOS
#endif // UDMF_TEMP_UDATA_LOADER_H
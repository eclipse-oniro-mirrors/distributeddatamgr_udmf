/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef UDMF_STORE_H
#define UDMF_STORE_H

#include <string>

#include "error_code.h"
#include "unified_data.h"
#include "unified_key.h"
#include "unified_types.h"

namespace OHOS {
namespace UDMF {
class Store {
public:
    virtual Status Put(const UnifiedData &unifiedData) = 0;
    virtual Status Get(const std::string &key, UnifiedData &unifiedData) = 0;
    virtual Status GetSummary(const std::string &key, Summary &summary) = 0;
    virtual Status Update(const UnifiedData &unifiedData) = 0;
    virtual Status Delete(const std::string &key) = 0;
    virtual Status DeleteBatch(const std::vector<std::string> &unifiedKeys) = 0;
    virtual Status Sync(const std::vector<std::string> &devices) = 0;
    virtual Status Clear() = 0;
    virtual bool Init() = 0;
    virtual void Close() = 0;
    virtual Status GetBatchData(const std::string &dataPrefix, std::vector<UnifiedData> &unifiedDataSet) = 0;
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_STORE_H

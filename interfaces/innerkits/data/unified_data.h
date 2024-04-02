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

#ifndef UDMF_UNIFIED_DATA_H
#define UDMF_UNIFIED_DATA_H

#include <string>
#include "unified_record.h"
#include "want_params.h"

namespace OHOS {
namespace UDMF {
enum ShareOption { IN_APP, CROSS_APP };
class UnifiedDataProperties {
public: 
    std::string tag;
    AAFwk::WantParams extras;
    ShareOption shareOption;
    double timestamp;
    std::function<void(std::string str)> call;
};

class UnifiedData {
public:
    int64_t GetSize();

    std::string GetGroupId() const;

    std::shared_ptr<Runtime> GetRuntime() const;
    void SetRuntime(Runtime &runtime);

    void AddRecord(const std::shared_ptr<UnifiedRecord> &record);
    std::shared_ptr<UnifiedRecord> GetRecordAt(std::size_t index);
    void SetRecords(std::vector<std::shared_ptr<UnifiedRecord>> records);
    std::vector<std::shared_ptr<UnifiedRecord>> GetRecords() const;

    std::vector<UDType> GetUDTypes();
    std::string GetTypes();
    std::vector<std::string> GetTypesVector();
    bool HasType(const std::string &type);

    bool IsEmpty() const;
    bool IsValid();
    bool IsComplete();

    static constexpr int64_t MAX_DATA_SIZE = 200 * 1024 * 1024;

private:
    std::shared_ptr<Runtime> runtime_;
    std::vector<std::shared_ptr<UnifiedRecord>> records_;
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_UNIFIED_DATA_H

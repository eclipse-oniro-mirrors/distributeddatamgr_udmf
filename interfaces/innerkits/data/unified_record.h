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

#ifndef UDMF_UNIFIED_RECORD_H
#define UDMF_UNIFIED_RECORD_H

#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "unified_types.h"

namespace OHOS {
namespace UDMF {
class UnifiedRecord {
public:
    UnifiedRecord();
    explicit UnifiedRecord(UDType type);
    virtual ~UnifiedRecord() = default;

    UDType GetType() const;
    void SetType(const UDType &type);
    virtual int64_t GetSize();

    std::string GetUid() const;
    void SetUid(const std::string &id);

protected:
    UDType dataType_;

private:
    std::string uid_; // unique identifier
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_UNIFIED_RECORD_H

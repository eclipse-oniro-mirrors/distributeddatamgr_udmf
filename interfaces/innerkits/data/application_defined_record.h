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

#ifndef UDMF_APPLICATION_DEFINED_RECORD_H
#define UDMF_APPLICATION_DEFINED_RECORD_H

#include "unified_record.h"
#include "visibility.h"
namespace OHOS {
namespace UDMF {
class ApplicationDefinedRecord : public UnifiedRecord {
public:
    API_EXPORT ApplicationDefinedRecord();
    explicit API_EXPORT ApplicationDefinedRecord(std::string type);
    explicit API_EXPORT ApplicationDefinedRecord(std::string type, std::vector<uint8_t> &data);
    API_EXPORT ApplicationDefinedRecord(UDType type, ValueType value);

    int64_t API_EXPORT GetSize() override;

    std::string API_EXPORT GetApplicationDefinedType() const;
    void API_EXPORT SetApplicationDefinedType(const std::string &type);

    std::vector<uint8_t> API_EXPORT GetRawData() const;
    void API_EXPORT SetRawData(const std::vector<uint8_t> &rawData);

    void InitObject() override;
protected:
    std::string applicationDefinedType;
    std::vector<uint8_t> rawData_;
};
} // namespace UDMF
} // namespace OHOS

#endif // UDMF_APPLICATION_DEFINED_RECORD_H

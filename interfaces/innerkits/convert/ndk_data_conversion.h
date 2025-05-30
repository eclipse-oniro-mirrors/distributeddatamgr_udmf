/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UDMF_DATA_CONVERSION_H
#define UDMF_DATA_CONVERSION_H

#include "unified_data.h"
#include "udmf.h"
#include "udmf_capi_common.h"
#include "error_code.h"

namespace OHOS::UDMF {
class NdkDataConversion {
public:
    static Status API_EXPORT GetNativeUnifiedData(OH_UdmfData* ndkData, std::shared_ptr<UnifiedData>& data);
    static Status API_EXPORT GetNdkUnifiedData(std::shared_ptr<UnifiedData> data, OH_UdmfData* ndkData);
    static char** StrVectorToTypesArray(const std::vector<std::string>& strVector);
    static void DestroyStringArray(char**& bufArray, unsigned int& count);
};
}

#endif // UDMF_DATA_CONVERSION_H
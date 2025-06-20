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

#ifndef UDMF_CUSTOM_UTD_STORE_H
#define UDMF_CUSTOM_UTD_STORE_H
#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdint>
#include "utd_common.h"
#include "custom_utd_json_parser.h"
namespace OHOS {
namespace UDMF {
class CustomUtdStore {
public:
    static CustomUtdStore &GetInstance();
    std::vector<TypeDescriptorCfg> GetCustomUtd(bool isHap, int32_t userId);
    int32_t SaveTypeCfgs(const std::vector<TypeDescriptorCfg> &customUtdTypes, int32_t user);
    bool InstallCustomUtds(const std::string &bundleName, const std::string &jsonStr, int32_t user,
        std::vector<TypeDescriptorCfg> &customTyepCfgs);
    bool UninstallCustomUtds(const std::string &bundleName, int32_t user,
        std::vector<TypeDescriptorCfg> &customTyepCfgs);
    UtdFileInfo GetCustomUtdInfo(bool isHap, int32_t userId);

private:
    CustomUtdStore();
    ~CustomUtdStore();
    int32_t SavaCfgFile(const std::string &jsonData, const std::string &cfgFilePath);
    bool CreateDirectory(const std::string &path) const;
    static void ProcessUtdForSave(const CustomUtdCfgs &utdTypes, std::vector<TypeDescriptorCfg> &customTyepCfgs,
        const std::string &bundleName);
    std::string GetCustomUtdPath(bool isHap, int32_t userId);

    CustomUtdJsonParser utdJsonParser_;
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_CUSTOM_UTD_STORE_H
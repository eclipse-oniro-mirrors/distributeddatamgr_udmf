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

#include "utd_cfgs_checker.h"

#include <vector>
#include <regex>
#include "utd_graph.h"
#include "logger.h"

namespace OHOS {
namespace UDMF {
UtdCfgsChecker::UtdCfgsChecker()
{
    LOG_INFO(UDMF_CLIENT, "construct UtdCfgsChecker sucess.");
}

UtdCfgsChecker::~UtdCfgsChecker()
{
}

UtdCfgsChecker &UtdCfgsChecker::GetInstance()
{
    static auto instance = new UtdCfgsChecker();
    return *instance;
}

bool UtdCfgsChecker::CheckTypeDescriptors(CustomUtdCfgs &typeCfgs, const std::vector<TypeDescriptorCfg> &presetCfgs,
    const std::vector<TypeDescriptorCfg> &customCfgs, const std::string &bundleName)
{
    if (!CheckTypesFormat(typeCfgs, bundleName)) {
        LOG_ERROR(UDMF_CLIENT, "CheckTypesFormat not pass");
        return false;
    }
    LOG_ERROR(UDMF_CLIENT, "CheckTypesFormat pass");
    if (!CheckTypesRelation(typeCfgs, presetCfgs, customCfgs)) {
        LOG_ERROR(UDMF_CLIENT, "CheckTypesRelation not pass");
        return false;
    }
    LOG_ERROR(UDMF_CLIENT, "CheckTypesRelation pass");
    return true;
}

bool UtdCfgsChecker::CheckTypesFormat(CustomUtdCfgs &typeCfgs, const std::string &bundleName)
{
    for (auto declarationType: typeCfgs.first) {
        if (!std::regex_match(declarationType.typeId, std::regex(bundleName + "[A_za-z0-9_.]+$"))) {
            LOG_ERROR(UDMF_CLIENT, "typeId is %{public}s.,",declarationType.typeId.c_str() );
            return false;
        }
    }
    for (auto referenceTypes: typeCfgs.second) {
        if (!std::regex_match(referenceTypes.typeId, std::regex("[A_za-z0-9_.]+$"))) {
            LOG_ERROR(UDMF_CLIENT, "typeId is %{public}s.,",referenceTypes.typeId.c_str() );
            return false;
        }
    }
    std::vector<TypeDescriptorCfg> inputTypeCfgs;
    if (!typeCfgs.first.empty()) {
        inputTypeCfgs.insert(inputTypeCfgs.end(), typeCfgs.first.begin(), typeCfgs.first.end());
    }
    if (!typeCfgs.second.empty()) {
        inputTypeCfgs.insert(inputTypeCfgs.end(), typeCfgs.second.begin(), typeCfgs.second.end());
    }
    for (TypeDescriptorCfg &typeCfg : inputTypeCfgs) {
        for (std::string filenames : typeCfg.filenameExtensions) {
            if (!filenames[0] == '.') {
                LOG_ERROR(UDMF_CLIENT, "File name extensions not valid, file names extensions: %{public}s.",
                    filenames.c_str());
                return false;
            }
        }
        if (typeCfg.belongingToTypes.empty()) {
            LOG_ERROR(UDMF_CLIENT, "BelongingToTypes can not be empty, bundleName: %{public}s.", bundleName.c_str());
            return false;
        }
    }
    return true;
}

bool UtdCfgsChecker::CheckTypesRelation(CustomUtdCfgs &typeCfgs, const std::vector<TypeDescriptorCfg> &presetCfgs,
    const std::vector<TypeDescriptorCfg> &customCfgs)
{
    std::vector<TypeDescriptorCfg> inputTypeCfgs;
    if (!typeCfgs.first.empty()) {
        inputTypeCfgs.insert(inputTypeCfgs.end(), typeCfgs.first.begin(), typeCfgs.first.end());
    }
    if (!typeCfgs.second.empty()) {
        inputTypeCfgs.insert(inputTypeCfgs.end(), typeCfgs.second.begin(), typeCfgs.second.end());
    }
    std::vector<TypeDescriptorCfg> inputAndPresetTypeCfgs;
    if (!presetCfgs.empty()) {
        inputAndPresetTypeCfgs.insert(inputAndPresetTypeCfgs.end(), inputTypeCfgs.begin(), inputTypeCfgs.end());
        inputAndPresetTypeCfgs.insert(inputAndPresetTypeCfgs.end(), presetCfgs.begin(), presetCfgs.end());
    }
    std::vector<std::string> typeIds;
    for (auto &typeCfg: inputAndPresetTypeCfgs) {
        LOG_ERROR(UDMF_CLIENT, "typeid is :%{public}s", typeCfg.typeId.c_str());
        typeIds.push_back(typeCfg.typeId);
    }
    if (std::set<std::string>(typeIds.begin(), typeIds.end()).size() != typeIds.size()) {
        LOG_ERROR(UDMF_CLIENT, "Can not set same typeIds.");
        return false;
    }
    for (auto customType : customCfgs) {
        typeIds.push_back(customType.typeId);
    }
    for (auto inputCfg : inputTypeCfgs) {
        for (std::string belong : inputCfg.belongingToTypes) {
            if (inputCfg.typeId == belong) {
                LOG_ERROR(UDMF_CLIENT, "TypeId cannot equals belongingToType, typeId: %{public}s.",
                    inputCfg.typeId.c_str());
                return false;
            }
            if (find(typeIds.begin(), typeIds.end(), belong) == typeIds.end()) {
                return false;
            }
        }
    }
    if (IsCircle(typeCfgs, presetCfgs, customCfgs)) {
        LOG_ERROR(UDMF_CLIENT, "is circle");
        return false;
    }
    return true;
}

bool UtdCfgsChecker::IsCircle(CustomUtdCfgs &typeCfgs, const std::vector<TypeDescriptorCfg> &presetCfgs,
    const std::vector<TypeDescriptorCfg> &customCfgs)
{
    std::vector<TypeDescriptorCfg> allTypeCfgs;
    if (!customCfgs.empty()) {
        allTypeCfgs.insert(allTypeCfgs.end(), customCfgs.begin(), customCfgs.end());
    }
    for (TypeDescriptorCfg &declarationType : typeCfgs.first) {
        for (auto iter = allTypeCfgs.begin(); iter != allTypeCfgs.end();) {
            if (iter->typeId == declarationType.typeId) {
                iter->belongingToTypes = declarationType.belongingToTypes;
                iter = allTypeCfgs.erase(iter);
            } else {
                iter ++;
            }
        }
        allTypeCfgs.push_back(declarationType);
    }
    for (TypeDescriptorCfg &referenceTypes : typeCfgs.second) {
        for (auto iter = allTypeCfgs.begin(); iter != allTypeCfgs.end();) {
            if (iter->typeId == referenceTypes.typeId) {
                iter = allTypeCfgs.erase(iter);
            } else {
                iter ++;
            }
        }
        allTypeCfgs.push_back(referenceTypes);
    }
    if (!presetCfgs.empty()) {
        allTypeCfgs.insert(allTypeCfgs.end(), presetCfgs.begin(), presetCfgs.end());
    }
    if (!allTypeCfgs.empty()) {
        UtdGraph::GetInstance().InitUtdGraph(allTypeCfgs);
        if (UtdGraph::GetInstance().IsDAG()) {
            LOG_ERROR(UDMF_CLIENT, "Parse failed because of has cycle");
            return true;
        }
    }
    return false;
}

} // namespace UDMF
} // namespace OHOS

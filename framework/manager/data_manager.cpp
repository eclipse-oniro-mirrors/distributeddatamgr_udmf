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

#include "data_manager.h"

#include "checker_manager.h"
#include "file.h"
#include "lifecycle/lifecycle_manager.h"
#include "logger.h"
#include "preprocess_utils.h"
#include "uri_permission_manager.h"

namespace OHOS {
namespace UDMF {
const std::string MSDP_PROCESS_NAME = "msdp_sa";
const std::string DATA_PREFIX = "udmf://";
DataManager::DataManager()
{
    authorizationMap_[UD_INTENTION_MAP.at(UD_INTENTION_DRAG)] = MSDP_PROCESS_NAME;
    CheckerManager::GetInstance().LoadCheckers();
}

DataManager::~DataManager()
{
}

DataManager &DataManager::GetInstance()
{
    static DataManager instance;
    return instance;
}

int32_t DataManager::SaveData(CustomOption &option, UnifiedData &unifiedData, std::string &key)
{
    if (unifiedData.IsEmpty()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid parameters, have no record");
        return E_INVALID_PARAMETERS;
    }

    if (!UnifiedDataUtils::IsValidIntention(option.intention)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid parameters intention: %{public}d.", option.intention);
        return E_INVALID_PARAMETERS;
    }

    // imput runtime info before put it into store and save one privilege
    PreProcessUtils utils = PreProcessUtils::GetInstance();
    if (!utils.RuntimeDataImputation(unifiedData, option)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Imputation failed, %{public}s", utils.errorStr.c_str());
        return E_UNKNOWN;
    }
    for (const auto &record : unifiedData.GetRecords()) {
        record->SetUid(PreProcessUtils::GetInstance().IdGenerator());
    }

    std::string intention = unifiedData.GetRuntime()->key.intention;
    auto store = storeCache_.GetStore(intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }

    if (!UnifiedDataUtils::IsPersist(intention) && store->Clear() != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Clear store failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }

    if (store->Put(unifiedData) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Put unified data failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }
    key = unifiedData.GetRuntime()->key.GetUnifiedKey();
    LOG_DEBUG(UDMF_FRAMEWORK, "Put unified data successful, key: %{public}s.", key.c_str());
    return E_OK;
}

int32_t DataManager::RetrieveData(const QueryOption &query, UnifiedData &unifiedData)
{
    UnifiedKey key(query.key);
    if (!key.IsValid()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unified key: %{public}s is invalid.", query.key.c_str());
        return E_INVALID_PARAMETERS;
    }
    auto store = storeCache_.GetStore(key.intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    int32_t res = store->Get(query.key, unifiedData);
    if (res != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get data from store failed, intention: %{public}s.", key.intention.c_str());
        return res;
    }
    if (unifiedData.IsEmpty()) {
        return E_OK;
    }
    std::shared_ptr<Runtime> runtime = unifiedData.GetRuntime();
    CheckerManager::CheckInfo info;
    info.tokenId = query.tokenId;
    if (!CheckerManager::GetInstance().IsValid(runtime->privileges, info)) {
        return E_NO_PERMISSION;
    }
    std::string bundleName;
    if (!PreProcessUtils::GetInstance().GetHapBundleNameByToken(query.tokenId, bundleName)) {
        return E_ERROR;
    }
    if (runtime->createPackage != bundleName) {
        auto records = unifiedData.GetRecords();
        for (auto record : records) {
            auto type = record->GetType();
            std::string uri = "";
            if (type == UDType::FILE || type == UDType::IMAGE || type == UDType::VIDEO || type == UDType::AUDIO
                || type == UDType::FOLDER) {
                auto file = static_cast<File *>(record.get());
                uri = file->GetUri();
            }
            if (!uri.empty() && (UriPermissionManager::GetInstance().GrantUriPermission(uri, bundleName) != E_OK)) {
                return E_NO_PERMISSION;
            }
        }
    }
    if (LifeCycleManager::GetInstance().DeleteOnGet(key) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Remove data failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

int32_t DataManager::RetrieveBatchData(const QueryOption &query, std::vector<UnifiedData> &unifiedDataSet)
{
    std::vector<UnifiedData> dataSet;
    std::shared_ptr<Store> store;
    auto status = QueryDataCommon(query, dataSet, store);
    if (status != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "QueryDataCommon failed.");
        return status;
    }
    if (dataSet.empty()) {
        LOG_WARN(UDMF_FRAMEWORK, "has no data, key: %{public}s, intention: %{public}d.", query.key.c_str(),
            query.intention);
        return E_OK;
    }
    for (const auto &data : dataSet) {
        unifiedDataSet.push_back(data);
    }
    return E_OK;
}

int32_t DataManager::UpdateData(const QueryOption &query, UnifiedData &unifiedData)
{
    UnifiedKey key(query.key);
    if (!key.IsValid()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unified key: %{public}s is invalid.", query.key.c_str());
        return E_INVALID_PARAMETERS;
    }
    if (unifiedData.IsEmpty()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid parameters, unified data has no record.");
        return E_INVALID_PARAMETERS;
    }
    auto store = storeCache_.GetStore(key.intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }

    UnifiedData data;
    int32_t res = store->Get(query.key, data);
    if (res != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get data from store failed, intention: %{public}s.", key.intention.c_str());
        return res;
    }
    if (data.IsEmpty()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid parameter, unified data has no record; intention: %{public}s.",
            key.intention.c_str());
        return E_INVALID_PARAMETERS;
    }
    std::shared_ptr<Runtime> runtime = data.GetRuntime();
    runtime->lastModifiedTime = PreProcessUtils::GetInstance().GetTimeStamp();
    unifiedData.SetRuntime(*runtime);
    for (const auto &record : unifiedData.GetRecords()) {
        record->SetUid(PreProcessUtils::GetInstance().IdGenerator());
    }
    if (store->Update(unifiedData) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Update unified data failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}
int32_t DataManager::DeleteData(const QueryOption &query, std::vector<UnifiedData> &unifiedDataSet)
{
    std::vector<UnifiedData> dataSet;
    std::shared_ptr<Store> store;
    auto status = QueryDataCommon(query, dataSet, store);
    if (status != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "QueryDataCommon failed.");
        return status;
    }
    if (dataSet.empty()) {
        LOG_WARN(UDMF_FRAMEWORK, "has no data, key: %{public}s, intention: %{public}d.", query.key.c_str(),
            query.intention);
        return E_OK;
    }
    std::shared_ptr<Runtime> runtime;
    std::vector<std::string> deleteKeys;
    for (const auto &data : dataSet) {
        runtime = data.GetRuntime();
        unifiedDataSet.push_back(data);
        deleteKeys.push_back(runtime->key.key);
    }
    if (store->DeleteBatch(deleteKeys) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Remove data failed.");
        return E_DB_ERROR;
    }
    return E_OK;
}

int32_t DataManager::GetSummary(const QueryOption &query, Summary &summary)
{
    UnifiedKey key(query.key);
    if (!key.IsValid()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unified key: %{public}s is invalid.", query.key.c_str());
        return E_INVALID_PARAMETERS;
    }

    auto store = storeCache_.GetStore(key.intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }

    if (store->GetSummary(query.key, summary) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Store get summary failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

int32_t DataManager::AddPrivilege(const QueryOption &query, const Privilege &privilege)
{
    UnifiedKey key(query.key);
    if (!key.IsValid()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unified key: %{public}s is invalid.", query.key.c_str());
        return E_INVALID_PARAMETERS;
    }

    std::string processName;
    PreProcessUtils utils = PreProcessUtils::GetInstance();
    if (!utils.GetNativeProcessNameByToken(query.tokenId, processName)) {
        LOG_ERROR(UDMF_FRAMEWORK, "%{public}s", utils.errorStr.c_str());
        return E_UNKNOWN;
    }

    if (processName != authorizationMap_[key.intention]) {
        LOG_ERROR(UDMF_FRAMEWORK, "Process: %{public}s have no permission", processName.c_str());
        return E_NO_PERMISSION;
    }

    auto store = storeCache_.GetStore(key.intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }

    UnifiedData data;
    int32_t res = store->Get(query.key, data);
    if (res != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get data from store failed, intention: %{public}s.", key.intention.c_str());
        return res;
    }

    if (data.IsEmpty()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid parameters, unified data has no record, intention: %{public}s.",
            key.intention.c_str());
        return E_INVALID_PARAMETERS;
    }

    data.GetRuntime()->privileges.emplace_back(privilege);
    if (store->Update(data) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Update unified data failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

int32_t DataManager::Sync(const QueryOption &query, const std::vector<std::string> &devices)
{
    UnifiedKey key(query.key);
    if (!key.IsValid()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unified key: %{public}s is invalid.", query.key.c_str());
        return E_INVALID_PARAMETERS;
    }

    auto store = storeCache_.GetStore(key.intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }

    if (store->Sync(devices) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Store sync failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

int32_t DataManager::QueryDataCommon(
    const QueryOption &query, std::vector<UnifiedData> &dataSet, std::shared_ptr<Store> &store)
{
    auto find = UD_INTENTION_MAP.find(query.intention);
    std::string intention = find == UD_INTENTION_MAP.end() ? intention : find->second;
    if (!UnifiedDataUtils::IsValidOptions(query.key, intention)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unified key: %{public}s and intention: %{public}s is invalid.", query.key.c_str(),
            intention.c_str());
        return E_INVALID_PARAMETERS;
    }
    std::string dataPrefix = DATA_PREFIX + intention;
    UnifiedKey key(query.key);
    key.IsValid();
    if (intention.empty()) {
        dataPrefix = key.key;
        intention = key.intention;
    }
    LOG_DEBUG(UDMF_FRAMEWORK, "dataPrefix = %{public}s, intention: %{public}s.", dataPrefix.c_str(), intention.c_str());
    store = storeCache_.GetStore(intention);
    if (store == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get store failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }
    if (store->GetBatchData(dataPrefix, dataSet) != E_OK) {
        LOG_ERROR(UDMF_FRAMEWORK, "Get dataSet failed, dataPrefix: %{public}s.", dataPrefix.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}
} // namespace UDMF
} // namespace OHOS
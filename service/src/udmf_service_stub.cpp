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

#include "udmf_service_stub.h"

#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "logger.h"
#include "tlv_util.h"
#include "udmf_service_utils.h"
#include "udmf_types_util.h"
#include "unified_data.h"
#include "unified_meta.h"
namespace OHOS {
namespace UDMF {
UdmfServiceStub::UdmfServiceStub()
{
    memberFuncMap_[static_cast<uint32_t>(SET_DATA)] = &UdmfServiceStub::OnSetData;
    memberFuncMap_[static_cast<uint32_t>(GET_DATA)] = &UdmfServiceStub::OnGetData;
    memberFuncMap_[static_cast<uint32_t>(GET_BATCH_DATA)] = &UdmfServiceStub::OnGetBatchData;
    memberFuncMap_[static_cast<uint32_t>(UPDATE_DATA)] = &UdmfServiceStub::OnUpdateData;
    memberFuncMap_[static_cast<uint32_t>(DELETE_DATA)] = &UdmfServiceStub::OnDeleteData;
    memberFuncMap_[static_cast<uint32_t>(GET_SUMMARY)] = &UdmfServiceStub::OnGetSummary;
    memberFuncMap_[static_cast<uint32_t>(ADD_PRIVILEGE)] = &UdmfServiceStub::OnAddPrivilege;
    memberFuncMap_[static_cast<uint32_t>(SYNC)] = &UdmfServiceStub::OnSync;
}

UdmfServiceStub::~UdmfServiceStub()
{
    memberFuncMap_.clear();
}

int UdmfServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start##code = %{public}u", code);
    std::u16string myDescripter = UdmfServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        LOG_ERROR(UDMF_SERVICE, "end##descriptor checked fail");
        return -1;
    }
    if (CODE_HEAD > code || code >= CODE_BUTT) {
        return -1;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    LOG_INFO(UDMF_SERVICE, "end##ret = -1");
    return -1;
}

int32_t UdmfServiceStub::OnSetData(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    CustomOption customOption;
    if (!ITypesUtil::Unmarshal(data, customOption)) {
        return IPC_STUB_INVALID_DATA_ERR;
    }
    UnifiedData unifiedData;
    if (UdmfServiceUtils::UnMarshalUnifiedData(data, unifiedData) != E_OK) {
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (unifiedData.GetRecords().empty()) {
        LOG_ERROR(UDMF_SERVICE, "Empty data without any record!");
        return E_INVALID_VALUE;
    }
    if (unifiedData.GetSize() > UdmfService::MAX_DATA_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "Exceeded data limit!");
        return E_INVALID_VALUE;
    }
    for (const auto &record : unifiedData.GetRecords()) {
        if (record->GetSize() > UdmfService::MAX_RECORD_SIZE) {
            return E_INVALID_VALUE;
        }
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    customOption.tokenId = token;
    std::string key;
    int32_t status = SetData(customOption, unifiedData, key);
    if (!ITypesUtil::Marshal(reply, status, key)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal key: %{public}s", key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetData(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    UnifiedData unifiedData;
    int32_t status = GetData(query, unifiedData);
    if (!ITypesUtil::Marshal(reply, status)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal ud data, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (UdmfServiceUtils::MarshalUnifiedData(reply, unifiedData) != E_OK) {
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetBatchData(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    std::vector<UnifiedData> unifiedDataSet;
    int32_t status = GetBatchData(query, unifiedDataSet);
    LOG_DEBUG(UDMF_SERVICE, "Getdata : status =  %{public}d!", status);
    if (!ITypesUtil::Marshal(reply, status)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal ud data, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (UdmfServiceUtils::MarshalBatchUnifiedData(reply, unifiedDataSet) != E_OK) {
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnUpdateData(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    UnifiedData unifiedData;
    if (UdmfServiceUtils::UnMarshalUnifiedData(data, unifiedData) != E_OK) {
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (unifiedData.GetRecords().empty()) {
        LOG_ERROR(UDMF_SERVICE, "Empty data without any record!");
        return E_INVALID_VALUE;
    }
    if (unifiedData.GetSize() > UdmfService::MAX_DATA_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "Exceeded data limit!");
        return E_INVALID_VALUE;
    }
    for (const auto &record : unifiedData.GetRecords()) {
        if (record->GetSize() > UdmfService::MAX_RECORD_SIZE) {
            return E_INVALID_VALUE;
        }
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = UpdateData(query, unifiedData);
    if (!ITypesUtil::Marshal(reply, status)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal update status failed, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnDeleteData(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    std::vector<UnifiedData> unifiedDataSet;
    int32_t status = DeleteData(query, unifiedDataSet);
    if (!ITypesUtil::Marshal(reply, status)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal ud data, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (UdmfServiceUtils::MarshalBatchUnifiedData(reply, unifiedDataSet) != E_OK) {
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetSummary(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    Summary summary;
    int32_t status = GetSummary(query, summary);
    if (!ITypesUtil::Marshal(reply, status, summary)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal summary, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnAddPrivilege(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    Privilege privilege;
    if (!ITypesUtil::Unmarshal(data, query, privilege)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query and privilege");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = AddPrivilege(query, privilege);
    if (!ITypesUtil::Marshal(reply, status)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal status, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnSync(MessageParcel &data, MessageParcel &reply)
{
    LOG_INFO(UDMF_SERVICE, "start");
    QueryOption query;
    std::vector<std::string> devices;
    if (!ITypesUtil::Unmarshal(data, query, devices)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshal query and devices");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = Sync(query, devices);
    if (!ITypesUtil::Marshal(reply, status)) {
        LOG_ERROR(UDMF_SERVICE, "Marshal status, key: %{public}s", query.key.c_str());
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

/*
 * Check whether the caller has the permission to access data.
 */
bool UdmfServiceStub::VerifyPermission(const std::string &permission)
{
#ifdef UDMF_PERMISSION_ENABLED
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    return result == Security::AccessToken::TypePermissionState::PERMISSION_GRANTED;
#else
    return true;
#endif // UDMF_PERMISSION_ENABLED
}
} // namespace UDMF
} // namespace OHOS
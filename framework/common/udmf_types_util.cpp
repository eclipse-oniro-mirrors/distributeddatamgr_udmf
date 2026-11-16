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
#define LOG_TAG "UdmfTypesUtil"
#include "udmf_types_util.h"

#include <utility>

#include "logger.h"
#include "tlv_util.h"

namespace OHOS {
namespace ITypesUtil {
using namespace UDMF;
static constexpr int32_t NORMAL_MAX_PARCEL_SIZE = 128 * 1024 * 1024;
template<>
bool Marshalling(const UnifiedData &input, MessageParcel &parcel)
{
    std::vector<uint8_t> dataBytes;
    auto recordTlv = TLVObject(dataBytes);
    if (!TLVUtil::Writing(input, recordTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_SERVICE, "TLV writing failed!");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(dataBytes.size()))
        || !parcel.WriteRawData(dataBytes.data(), dataBytes.size())) {
        LOG_ERROR(UDMF_SERVICE, "Marshall unified data failed!");
        return false;
    }
    return true;
}

template<>
bool Unmarshalling(UnifiedData &output, MessageParcel &parcel)
{
    auto dataSize = parcel.GetDataSize();
    auto size = parcel.ReadInt32();
    if (size <= 0 || size > UnifiedData::MAX_DATA_SIZE || dataSize > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE,
            "UnifiedData is empty or too large, dataSize is %{public}zu, size is %{public}d", dataSize, size);
        return false;
    }
    auto rawData = parcel.ReadRawData(size);
    if (rawData == nullptr) {
        LOG_ERROR(UDMF_SERVICE, "RawData is null!");
        return false;
    }
    const uint8_t *data = reinterpret_cast<const uint8_t *>(rawData);
    std::vector<uint8_t> dataBytes(data, data + size);
    auto dataTlv = TLVObject(dataBytes);
    if (!TLVUtil::ReadTlv(output, dataTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshall unified data failed!");
        return false;
    }
    return true;
}

template<>
bool Marshalling(const std::vector<UnifiedData> &input, MessageParcel &parcel)
{
    std::vector<uint8_t> dataSetBytes;
    auto recordTlv = TLVObject(dataSetBytes);
    if (!TLVUtil::Writing(input, recordTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_SERVICE, "TLV writing failed!");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(dataSetBytes.size()))
        || !parcel.WriteRawData(dataSetBytes.data(), dataSetBytes.size())) {
        LOG_ERROR(UDMF_SERVICE, "Marshall unified data set failed!");
        return false;
    }
    return true;
}

template<>
bool Unmarshalling(std::vector<UnifiedData> &output, MessageParcel &parcel)
{
    auto dataSize = parcel.GetDataSize();
    auto size = parcel.ReadInt32();
    if (size <= 0 || size > UnifiedData::MAX_DATA_SIZE || dataSize > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE,
            "UnifiedDataList is empty or too large, dataSize is %{public}zu, size is %{public}d", dataSize, size);
        return false;
    }
    const uint8_t *rawData = reinterpret_cast<const uint8_t *>(parcel.ReadRawData(size));
    if (rawData == nullptr) {
        LOG_ERROR(UDMF_SERVICE, "RawData is null!");
        return false;
    }
    std::vector<uint8_t> dataSetBytes(rawData, rawData + size);
    auto dataTlv = TLVObject(dataSetBytes);
    if (!TLVUtil::ReadTlv(output, dataTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshall unified data set failed!");
        return false;
    }
    return true;
}

template<>
bool Marshalling(const Summary &input, MessageParcel &parcel)
{
    return ITypesUtil::Marshal(parcel, input.summary, input.totalSize, input.specificSummary,
        input.summaryFormat, input.version, input.tag, input.filenameExtensions);
}

template<>
bool Unmarshalling(Summary &output, MessageParcel &parcel)
{
    auto dataSize = parcel.GetDataSize();
    if (dataSize <= 0 || dataSize > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "UnifiedData is empty or too large, dataSize is %{public}zu", dataSize);
        return false;
    }
    return ITypesUtil::Unmarshal(parcel, output.summary, output.totalSize, output.specificSummary,
        output.summaryFormat, output.version, output.tag, output.filenameExtensions);
}

template<>
bool Marshalling(const Privilege &input, MessageParcel &parcel)
{
    return ITypesUtil::Marshal(parcel, input.tokenId, input.readPermission, input.writePermission);
}

template<>
bool Unmarshalling(Privilege &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "Privilege is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    return ITypesUtil::Unmarshal(parcel, output.tokenId, output.readPermission, output.writePermission);
}

template<>
bool Marshalling(const CustomOption &input, MessageParcel &parcel)
{
    return ITypesUtil::Marshal(parcel, input.intention, input.visibility);
}

template<>
bool Unmarshalling(CustomOption &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "CustomOption is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    return ITypesUtil::Unmarshal(parcel, output.intention, output.visibility);
}

template<>
bool Marshalling(const QueryOption &input, MessageParcel &parcel)
{
    return ITypesUtil::Marshal(parcel, input.key, input.intention);
}

template<>
bool Unmarshalling(QueryOption &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "QueryOption is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    return ITypesUtil::Unmarshal(parcel, output.key, output.intention);
}

template<>
bool Marshalling(const UDType &input, MessageParcel &parcel)
{
    int32_t type = input;
    return ITypesUtil::Marshal(parcel, type);
}

template<>
bool Unmarshalling(UDType &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_FRAMEWORK, "UDType is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    int32_t type;
    if (!ITypesUtil::Unmarshal(parcel, type)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unmarshal UDType failed!");
        return false;
    }
    if (type < ENTITY || type >= UD_BUTT) {
        LOG_ERROR(UDMF_FRAMEWORK, "invalid UDType!");
        return false;
    }
    output = static_cast<UDType>(type);
    return true;
}

template<>
bool Marshalling(const Intention &input, MessageParcel &parcel)
{
    int32_t intention = input;
    return ITypesUtil::Marshal(parcel, intention);
}

template<>
bool Unmarshalling(Intention &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_FRAMEWORK, "Intention is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    int32_t intention;
    if (!ITypesUtil::Unmarshal(parcel, intention)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unmarshal Intention failed!");
        return false;
    }
    if (intention < UD_INTENTION_BASE || intention > UD_INTENTION_BUTT) {
        LOG_ERROR(UDMF_FRAMEWORK, "invalid Intention!");
        return false;
    }
    output = static_cast<Intention>(intention);
    return true;
}

template<>
bool Marshalling(const Visibility &input, MessageParcel &parcel)
{
    int32_t visibility = input;
    return ITypesUtil::Marshal(parcel, visibility);
}

template<>
bool Unmarshalling(Visibility &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_FRAMEWORK, "Visibility is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    int32_t visibility;
    if (!ITypesUtil::Unmarshal(parcel, visibility)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unmarshal Visibility failed!");
        return false;
    }
    if (visibility < VISIBILITY_ALL || visibility >= VISIBILITY_BUTT) {
        LOG_ERROR(UDMF_FRAMEWORK, "invalid visibility : %{public}d", visibility);
        return false;
    }
    output = static_cast<Visibility>(visibility);
    return true;
}

template<>
bool Marshalling(const AsyncProcessInfo &input, MessageParcel &parcel)
{
    uint32_t syncStatus = input.syncStatus;
    uint32_t permStatus = input.permStatus;
    return ITypesUtil::Marshal(parcel, syncStatus, permStatus, input.srcDevName, input.syncFinished, input.syncTotal,
        input.syncId, input.permFnished, input.permTotal, input.businessUdKey);
}

template<>
bool Unmarshalling(AsyncProcessInfo &output, MessageParcel &parcel)
{
    auto size = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_FRAMEWORK, "AsyncProcessInfo is empty or too large, dataSize is %{public}zu", size);
        return false;
    }
    uint32_t syncStatus;
    uint32_t permStatus;
    if (!ITypesUtil::Unmarshal(parcel, syncStatus, permStatus, output.srcDevName, output.syncFinished, output.syncTotal,
        output.syncId, output.permFnished, output.permTotal, output.businessUdKey)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Unmarshal AsyncProcessInfo failed!");
        return false;
    }

    if (syncStatus > ASYNC_FAILURE || permStatus > ASYNC_FAILURE) {
        LOG_ERROR(UDMF_FRAMEWORK, "invalid SyncStatus!");
        return false;
    }
    output.syncStatus = static_cast<AsyncTaskStatus>(syncStatus);
    output.permStatus = static_cast<AsyncTaskStatus>(permStatus);
    return true;
}

template<>
bool Marshalling(const DataLoadInfo &input, MessageParcel &parcel)
{
    std::vector<uint8_t> dataSetBytes;
    auto recordTlv = TLVObject(dataSetBytes);
    if (!TLVUtil::Writing(input, recordTlv, TAG::TAG_DATA_LOAD_INFO)) {
        LOG_ERROR(UDMF_SERVICE, "TLV writing failed!");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(dataSetBytes.size()))
        || !parcel.WriteRawData(dataSetBytes.data(), dataSetBytes.size())) {
        LOG_ERROR(UDMF_SERVICE, "Marshall dataLoadInfo failed!");
        return false;
    }
    return true;
}

template<>
bool Unmarshalling(DataLoadInfo &output, MessageParcel &parcel)
{
    auto size = parcel.ReadInt32();
    auto dataSize = parcel.GetDataSize();
    if (size <= 0 || size > NORMAL_MAX_PARCEL_SIZE || dataSize > NORMAL_MAX_PARCEL_SIZE) {
        LOG_ERROR(UDMF_SERVICE,
            "DataLoadInfo is empty or too large, dataSize is %{public}zu, size is %{public}d", dataSize, size);
        return false;
    }
    const uint8_t *rawData = reinterpret_cast<const uint8_t *>(parcel.ReadRawData(size));
    if (rawData == nullptr) {
        LOG_ERROR(UDMF_SERVICE, "RawData is null!");
        return false;
    }
    std::vector<uint8_t> dataSetBytes(rawData, rawData + size);
    auto dataTlv = TLVObject(dataSetBytes);
    if (!TLVUtil::ReadTlv(output, dataTlv, TAG::TAG_DATA_LOAD_INFO)) {
        LOG_ERROR(UDMF_SERVICE, "Unmarshall dataLoadInfo failed!");
        return false;
    }
    return true;
}

namespace {
constexpr uint32_t VIRTUAL_ENTRY_VERSION = 1;
// A maximum-length 4096-node tree fits within this rounded, bounded budget.
constexpr uint32_t VIRTUAL_ENTRY_MAX_BYTES = 8 * 1024 * 1024;
constexpr uint32_t VIRTUAL_ENTRY_MAX_COUNT = 4096;
constexpr uint32_t VIRTUAL_ENTRY_MAX_DEPTH = 64;
constexpr size_t VIRTUAL_ENTRY_MAX_ID_BYTES = 1024;
constexpr size_t VIRTUAL_ENTRY_MAX_NAME_BYTES = 255;

bool WriteVirtualEntryNode(Parcel &parcel, const VirtualEntry &entry, uint32_t &count, uint32_t depth)
{
    if (depth > VIRTUAL_ENTRY_MAX_DEPTH || count >= VIRTUAL_ENTRY_MAX_COUNT ||
        entry.id.size() > VIRTUAL_ENTRY_MAX_ID_BYTES || entry.name.size() > VIRTUAL_ENTRY_MAX_NAME_BYTES ||
        entry.subItems.size() > VIRTUAL_ENTRY_MAX_COUNT - count - 1 ||
        (entry.type != VirtualEntryType::FILE && entry.type != VirtualEntryType::DIRECTORY) ||
        (entry.type == VirtualEntryType::FILE && (entry.size < 0 || !entry.subItems.empty()))) {
        return false;
    }
    ++count;
    if (!parcel.WriteString(entry.id) || !parcel.WriteString(entry.name) ||
        !parcel.WriteInt32(static_cast<int32_t>(entry.type)) || !parcel.WriteInt64(entry.modifyTime) ||
        !parcel.WriteInt64(entry.size) || !parcel.WriteUint32(static_cast<uint32_t>(entry.subItems.size()))) {
        return false;
    }
    for (const auto &child : entry.subItems) {
        if (!WriteVirtualEntryNode(parcel, child, count, depth + 1)) {
            return false;
        }
    }
    return true;
}

bool ReadVirtualEntryNode(Parcel &parcel, VirtualEntry &entry, uint32_t &count, uint32_t depth)
{
    if (depth > VIRTUAL_ENTRY_MAX_DEPTH || count >= VIRTUAL_ENTRY_MAX_COUNT) {
        return false;
    }
    ++count;
    int32_t type = 0;
    uint32_t childCount = 0;
    if (!parcel.ReadString(entry.id) || entry.id.size() > VIRTUAL_ENTRY_MAX_ID_BYTES || !parcel.ReadString(entry.name) ||
        entry.name.size() > VIRTUAL_ENTRY_MAX_NAME_BYTES || !parcel.ReadInt32(type) || !parcel.ReadInt64(entry.modifyTime) ||
        !parcel.ReadInt64(entry.size) || !parcel.ReadUint32(childCount) || childCount > VIRTUAL_ENTRY_MAX_COUNT - count ||
        type < static_cast<int32_t>(VirtualEntryType::FILE) ||
        type > static_cast<int32_t>(VirtualEntryType::DIRECTORY)) {
        return false;
    }
    entry.type = static_cast<VirtualEntryType>(type);
    if (entry.type == VirtualEntryType::FILE && (entry.size < 0 || childCount != 0)) {
        return false;
    }
    entry.subItems.reserve(childCount);
    for (uint32_t index = 0; index < childCount; ++index) {
        VirtualEntry child;
        if (!ReadVirtualEntryNode(parcel, child, count, depth + 1)) {
            return false;
        }
        entry.subItems.emplace_back(std::move(child));
    }
    return true;
}
} // namespace

template<>
bool Marshalling(const VirtualEntry &entry, MessageParcel &parcel)
{
    Parcel payload;
    uint32_t count = 0;
    if (!payload.SetMaxCapacity(VIRTUAL_ENTRY_MAX_BYTES) || !WriteVirtualEntryNode(payload, entry, count, 0)) {
        return false;
    }
    return parcel.WriteUint32(VIRTUAL_ENTRY_VERSION) &&
        parcel.WriteUint32(static_cast<uint32_t>(payload.GetDataSize())) &&
        parcel.WriteRawData(reinterpret_cast<const void *>(payload.GetData()), payload.GetDataSize());
}

template<>
bool Unmarshalling(VirtualEntry &entry, MessageParcel &parcel)
{
    uint32_t version = 0;
    uint32_t size = 0;
    if (!parcel.ReadUint32(version) || version != VIRTUAL_ENTRY_VERSION || !parcel.ReadUint32(size) || size == 0 ||
        size > VIRTUAL_ENTRY_MAX_BYTES) {
        return false;
    }
    const void *bytes = parcel.ReadRawData(size);
    Parcel payload;
    // Decode an owned snapshot rather than a mapping writable by the remote process.
    if (bytes == nullptr || !payload.SetMaxCapacity(VIRTUAL_ENTRY_MAX_BYTES) || !payload.WriteBuffer(bytes, size)) {
        return false;
    }
    uint32_t count = 0;
    VirtualEntry decoded;
    if (!ReadVirtualEntryNode(payload, decoded, count, 0) || payload.GetReadableBytes() != 0) {
        return false;
    }
    entry = std::move(decoded);
    return true;
}
} // namespace ITypesUtil
} // namespace OHOS

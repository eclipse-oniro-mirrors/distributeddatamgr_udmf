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
#include <variant>
#define LOG_TAG "UnifiedDataHelper"
#include "unified_data_helper.h"

#include "common_func.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "file_uri.h"
#include "error_code.h"
#include "logger.h"
#include "tlv_util.h"
#include "udmf_conversion.h"
#include "udmf_utils.h"
#include "file.h"

namespace OHOS {
namespace UDMF {
constexpr mode_t MODE = 0700;
static constexpr int64_t MAX_HAP_RECORD_SIZE = 2 * 1024 * 1024;
static constexpr int64_t MAX_HAP_DATA_SIZE = 4 * 1024 * 1024;
static constexpr int64_t MAX_IPC_RAW_DATA_SIZE = 128 * 1024 * 1024;
static constexpr int64_t MAX_SA_DRAG_RECORD_SIZE  = 15 * 1024 * 1024 + 512 * 1024;

constexpr const char *TEMP_UNIFIED_DATA_ROOT_PATH = "data/storage/el2/base/temp/udata";
constexpr const char *TEMP_UNIFIED_DATA_SUFFIX = ".ud";
constexpr const char *TEMP_UNIFIED_DATA_FLAG = "temp_udmf_file_flag";

std::string UnifiedDataHelper::rootPath_ = "";

void UnifiedDataHelper::SetRootPath(const std::string &rootPath)
{
    rootPath_ = rootPath;
}

bool UnifiedDataHelper::ExceedKVSizeLimit(UnifiedData &data)
{
    int64_t totalSize = 0;
    for (const auto &record : data.GetRecords()) {
        auto recordSize = record->GetSize();
        if (recordSize > MAX_HAP_RECORD_SIZE) {
            LOG_INFO(UDMF_FRAMEWORK, "Exceeded 2M record limit, recordSize:%{public}" PRId64 "!", recordSize);
            return true;
        }
        totalSize += recordSize;
    }
    if (totalSize > MAX_HAP_DATA_SIZE) {
        LOG_INFO(UDMF_FRAMEWORK, "Exceeded 4M data limit, totalSize:%{public}" PRId64 " !", totalSize);
        return true;
    }
    return false;
}

bool UnifiedDataHelper::IsTempUData(UnifiedData &data)
{
    auto records = data.GetRecords();
    if (records.size() != 1) {
        return false;
    }
    if (records[0] == nullptr || records[0]->GetType() != UDType::FILE) {
        return false;
    }
    auto file = static_cast<File*>(records[0].get());
    if (file == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid file record!");
        return false;
    }
    auto details = file->GetDetails();
    if (details.find(TEMP_UNIFIED_DATA_FLAG) == details.end()) {
        return false;
    }
    LOG_DEBUG(UDMF_FRAMEWORK, "exist temp unified data flag!");
    return true;
}

void UnifiedDataHelper::CreateDirIfNotExist(const std::string& dirPath, const mode_t& mode)
{
    if (OHOS::FileExists(dirPath)) {
        if (!OHOS::ForceRemoveDirectory(dirPath)) {
            LOG_ERROR(UDMF_FRAMEWORK, "remove dir %{public}s failed, errno: %{public}d.", dirPath.c_str(), errno);
        }
    }
    LOG_DEBUG(UDMF_FRAMEWORK, "ForceCreateDirectory, dir: %{public}s", dirPath.c_str());
    bool success = OHOS::ForceCreateDirectory(dirPath);
    if (!success) {
        LOG_ERROR(UDMF_FRAMEWORK, "create dir %{public}s failed, errno: %{public}d.", dirPath.c_str(), errno);
        return;
    }
    if (mode != 0) {
        chmod(dirPath.c_str(), mode);
    }
}

void UnifiedDataHelper::GetSummary(const UnifiedData &data, Summary &summary)
{
    for (const auto &record : data.GetRecords()) {
        auto entry = *record->GetEntries();
        for (const auto &[utdId, value] : entry) {
            auto typeId = utdId;
            auto valueSize = ObjectUtils::GetValueSize(value, false);
            if (std::holds_alternative<std::shared_ptr<Object>>(value)) {
                auto object = std::get<std::shared_ptr<Object>>(value);
                if (object->value_.find("UDCConverFlag") != object->value_.end()) {
                    typeId = "ApplicationDefinedType";
                }
            }
            auto it = summary.summary.find(utdId);
            if (it == summary.summary.end()) {
                summary.summary[utdId] = valueSize;
            } else {
                summary.summary[utdId] += valueSize;
            }
            summary.totalSize += valueSize;
        }
    }
}

bool UnifiedDataHelper::Pack(UnifiedData &data)
{
    UdmfConversion::InitValueObject(data);

    Summary summary;
    GetSummary(data, summary);

    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>
                    (std::chrono::system_clock::now().time_since_epoch()).count();
    CreateDirIfNotExist(GetRootPath(), MODE);
    std::string filePath = GetRootPath() + std::to_string(now) + TEMP_UNIFIED_DATA_SUFFIX;
    if (!SaveUDataToFile(filePath, data)) {
        LOG_ERROR(UDMF_FRAMEWORK, "fail to save unified data to file");
        return false;
    }
    std::string uri = AppFileService::CommonFunc::GetUriFromPath(filePath);
    auto fileRecord = std::make_shared<File>(uri);
    UDDetails details;
    details.insert(std::make_pair(TEMP_UNIFIED_DATA_FLAG, true));
    for (auto &item : summary.summary) {
        details.insert(std::make_pair(item.first, item.second));
    }
    fileRecord->SetDetails(details);
    std::vector<std::shared_ptr<UnifiedRecord>> records {};
    records.emplace_back(fileRecord);
    data.SetRecords(records);
    return true;
}

bool UnifiedDataHelper::Unpack(UnifiedData &data)
{
    auto records = data.GetRecords();
    if (records.size() != 1) {
        return false;
    }

    auto file = static_cast<File*>(records[0].get());
    if (file == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid file record!");
        return false;
    }
    UnifiedData tempData;
    if (!LoadUDataFromFile(file->GetUri(), tempData)) {
        LOG_ERROR(UDMF_FRAMEWORK, "Fail to load udata from file!");
        return false;
    }
    data.SetRecords(tempData.GetRecords());
    return true;
}

bool UnifiedDataHelper::SaveUDataToFile(const std::string &dataFile, UnifiedData &data)
{
    std::vector<uint8_t> dataBytes;
    auto recordTlv = TLVObject(dataBytes);

    std::FILE *file = fopen(dataFile.c_str(), "w+");
    if (file == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "failed to open file: %{public}s, errno is %{public}d", dataFile.c_str(), errno);
        return false;
    }
    recordTlv.SetFile(file);
    UdmfConversion::InitValueObject(data);
    if (!TLVUtil::Writing(data, recordTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_FRAMEWORK, "TLV Writing failed!");
        (void)fclose(file);
        return false;
    }
    (void)fclose(file);
    return true;
}

bool UnifiedDataHelper::LoadUDataFromFile(const std::string &dataFile, UnifiedData &data)
{
    std::vector<uint8_t> dataBytes;
    auto recordTlv = TLVObject(dataBytes);
    AppFileService::ModuleFileUri::FileUri fileUri(dataFile);
    std::string path = fileUri.GetRealPath();
    std::FILE *file = fopen(path.c_str(), "r");
    if (file == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "failed to open file, error:%{public}s, srcdir:%{public}s, relPath:%{public}s",
                  std::strerror(errno),
                  dataFile.c_str(),
                  path.c_str());
        return false;
    }
    recordTlv.SetFile(file);
	
    if (!TLVUtil::ReadTlv(data, recordTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_FRAMEWORK, "TLV Reading failed!");
        (void)fclose(file);
        return false;
    }
    UdmfConversion::ConvertRecordToSubclass(data);
    (void)fclose(file);
    return true;
}

std::string UnifiedDataHelper::GetRootPath()
{
    if (rootPath_ == "") {
        return TEMP_UNIFIED_DATA_ROOT_PATH;
    }
    return rootPath_;
}

int32_t UnifiedDataHelper::ProcessBigData(UnifiedData &data, Intention intention, bool isSaInvoke)
{
    if (!isSaInvoke) {
        return UnifiedDataHelper::Pack(data) ? E_OK : E_FS_ERROR;
    }
    if (intention != Intention::UD_INTENTION_DRAG) {
        LOG_ERROR(UDMF_SERVICE, "Non-Drag cannot be used to process big data when SA initiates a request");
        return E_INVALID_PARAMETERS;
    }
    int64_t dataSize = 0;
    for (const auto &record : data.GetRecords()) {
        auto recordSize = record->GetSize();
        if (recordSize > MAX_SA_DRAG_RECORD_SIZE) {
            LOG_ERROR(UDMF_FRAMEWORK, "Exceeded KV record limit, recordSize:%{public}" PRId64 "!", recordSize);
            return E_INVALID_PARAMETERS;
        }
        dataSize += recordSize;
    }
    if (dataSize > MAX_IPC_RAW_DATA_SIZE) {
        LOG_ERROR(UDMF_SERVICE, "Exceeded ipc-send data limit, totalSize:%{public}" PRId64 " !", dataSize);
        return E_INVALID_PARAMETERS;
    }
    LOG_DEBUG(UDMF_SERVICE, "Processing udmf data in memory");
    return E_OK;
}

} // namespace UDMF
} // namespace OHOS
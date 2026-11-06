/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define LOG_TAG "TempUDataLoader"

#include "temp_udata_loader.h"

#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include "file_uri.h"
#include "logger.h"
#include "tlv_util.h"
#include "unified_data_extension.h"

namespace OHOS {
namespace UDMF {
constexpr int64_t FILE_SIZE_OVERHEAD = 10 * 1024 * 1024;

bool TempUDataLoader::FileClose(std::FILE *file, bool status)
{
    if (file == nullptr) {
        return false;
    }
    if (fclose(file) == EOF) {
        LOG_ERROR(UDMF_FRAMEWORK, "fclose is failed");
        return false;
    }
    return status;
}

bool TempUDataLoader::IsTempUData(const UnifiedData &data)
{
    auto records = data.GetRecords();
    if (records.size() != 1) {
        return false;
    }
    if (records[0] == nullptr || records[0]->GetType() != UDType::FILE) {
        return false;
    }
    return HasTempUnifiedDataFlag(records[0]);
}

bool TempUDataLoader::Decode(const UnifiedData &packed, UnifiedData &decoded)
{
    auto records = packed.GetRecords();
    if (records.size() != 1 || records[0] == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid temp file record!");
        return false;
    }
    auto uri = GetFileUriFromRecord(records[0]);
    if (uri.empty()) {
        LOG_ERROR(UDMF_FRAMEWORK, "Invalid file record!");
        return false;
    }
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();
    std::FILE *file = fopen(path.c_str(), "r");
    if (file == nullptr) {
        LOG_ERROR(UDMF_FRAMEWORK, "failed to open file, error:%{public}s", std::strerror(errno));
        return false;
    }
    struct stat fileInfo;
    if (fstat(fileno(file), &fileInfo) != 0 ||
        fileInfo.st_size > UnifiedData::MAX_DATA_SIZE + FILE_SIZE_OVERHEAD) {
        LOG_ERROR(UDMF_FRAMEWORK, "failed to get file size or file size exceeds limit");
        return FileClose(file, false);
    }
    std::vector<uint8_t> dataBytes;
    auto recordTlv = TLVObject(dataBytes);
    recordTlv.SetFile(file);
    if (!TLVUtil::ReadTlv(decoded, recordTlv, TAG::TAG_UNIFIED_DATA)) {
        LOG_ERROR(UDMF_FRAMEWORK, "TLV Reading failed!");
        return FileClose(file, false);
    }
    return FileClose(file, true);
}
} // namespace UDMF
} // namespace OHOS
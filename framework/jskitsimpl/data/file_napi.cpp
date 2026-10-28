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
#define LOG_TAG "FileNapi"
#include "file_napi.h"

#include <algorithm>
#include <utility>

#include "file.h"
#include "histogram_wrapper.h"
#include "unified_record_napi.h"
#include "uri_permission_util.h"
#include "virtual_entry_napi.h"

namespace OHOS {
namespace UDMF {
namespace {
constexpr uint32_t MAX_VIRTUAL_ENTRY_DEPTH = 64;
constexpr uint32_t MAX_VIRTUAL_ENTRY_COUNT = 4096;
constexpr size_t MAX_VIRTUAL_ENTRY_NAME_BYTES = 255;
constexpr size_t MAX_VIRTUAL_ENTRY_ID_BYTES = 1024;

bool GetNamedProperty(napi_env env, napi_value object, const char *name, napi_value &value)
{
    bool hasProperty = false;
    return napi_has_named_property(env, object, name, &hasProperty) == napi_ok && hasProperty &&
           napi_get_named_property(env, object, name, &value) == napi_ok;
}

bool IsFunction(napi_env env, napi_value value)
{
    napi_valuetype type = napi_undefined;
    return napi_typeof(env, value, &type) == napi_ok && type == napi_function;
}

bool IsValidName(const std::string &name)
{
    return !name.empty() && name.size() <= MAX_VIRTUAL_ENTRY_NAME_BYTES && name != "." && name != ".." &&
           name.find_first_of("/\\") == std::string::npos && name.find('\0') == std::string::npos;
}

bool ParseVirtualItem(napi_env env, napi_value value, VirtualEntry &item, uint32_t depth, uint32_t &itemCount);

bool ParseCommonFields(napi_env env, napi_value value, VirtualEntry &item, std::string &itemType)
{
    napi_value property = nullptr;
    return GetNamedProperty(env, value, "name", property) &&
           NapiDataUtils::GetValue(env, property, item.name) == napi_ok && IsValidName(item.name) &&
           GetNamedProperty(env, value, "type", property) &&
           NapiDataUtils::GetValue(env, property, itemType) == napi_ok &&
           GetNamedProperty(env, value, "modifyTime", property) &&
           NapiDataUtils::GetValue(env, property, item.modifyTime) == napi_ok;
}

bool ParseVirtualFile(napi_env env, napi_value value, VirtualEntry &item)
{
    napi_value property = nullptr;
    item.type = VirtualEntryType::FILE;
    if (!GetNamedProperty(env, value, "id", property) ||
        NapiDataUtils::GetValue(env, property, item.id) != napi_ok || item.id.empty() ||
        item.id.size() > MAX_VIRTUAL_ENTRY_ID_BYTES) {
        return false;
    }
    if (!GetNamedProperty(env, value, "size", property) || NapiDataUtils::IsUndefinedOrNull(env, property)) {
        return true;
    }
    return NapiDataUtils::GetValue(env, property, item.size) == napi_ok && item.size >= 0;
}

bool ParseVirtualDirectory(
    napi_env env, napi_value value, VirtualEntry &item, uint32_t depth, uint32_t &itemCount)
{
    napi_value property = nullptr;
    item.type = VirtualEntryType::DIRECTORY;
    if (!GetNamedProperty(env, value, "subItems", property) || NapiDataUtils::IsUndefinedOrNull(env, property)) {
        return true;
    }
    bool isArray = false;
    uint32_t length = 0;
    if (napi_is_array(env, property, &isArray) != napi_ok || !isArray ||
        napi_get_array_length(env, property, &length) != napi_ok) {
        return false;
    }
    item.subItems.reserve(length);
    for (uint32_t index = 0; index < length; ++index) {
        napi_value child = nullptr;
        VirtualEntry childItem;
        if (napi_get_element(env, property, index, &child) != napi_ok ||
            !ParseVirtualItem(env, child, childItem, depth + 1, itemCount)) {
            return false;
        }
        item.subItems.emplace_back(std::move(childItem));
    }
    return true;
}

bool ParseVirtualItem(napi_env env, napi_value value, VirtualEntry &item, uint32_t depth, uint32_t &itemCount)
{
    napi_valuetype type = napi_undefined;
    if (depth > MAX_VIRTUAL_ENTRY_DEPTH || itemCount >= MAX_VIRTUAL_ENTRY_COUNT ||
        napi_typeof(env, value, &type) != napi_ok || type != napi_object) {
        return false;
    }
    ++itemCount;
    std::string itemType;
    if (!ParseCommonFields(env, value, item, itemType)) {
        return false;
    }
    if (itemType == "file") {
        return ParseVirtualFile(env, value, item);
    }
    return itemType == "dir" && ParseVirtualDirectory(env, value, item, depth, itemCount);
}

bool NeedsStatCallback(const VirtualEntry &entry)
{
    if (entry.type == VirtualEntryType::FILE) {
        return entry.size < 0;
    }
    return std::any_of(entry.subItems.begin(), entry.subItems.end(), NeedsStatCallback);
}

bool IsVirtualEntryProvider(napi_env env, napi_value value, bool &hasOnStat)
{
    hasOnStat = false;
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, value, &type) != napi_ok || type != napi_object) {
        return false;
    }
    napi_value callback = nullptr;
    if (!GetNamedProperty(env, value, "onRead", callback) || !IsFunction(env, callback) ||
        !GetNamedProperty(env, value, "onCancel", callback) || !IsFunction(env, callback)) {
        return false;
    }
    if (GetNamedProperty(env, value, "onStat", callback) && !NapiDataUtils::IsUndefinedOrNull(env, callback)) {
        if (!IsFunction(env, callback)) {
            return false;
        }
        hasOnStat = true;
    }
    return true;
}
} // namespace

bool FileNapi::AttachVirtualEntry(napi_env env, napi_value fileUri, const std::shared_ptr<File> &file)
{
    if (env == nullptr || fileUri == nullptr || file == nullptr) {
        return false;
    }
    bool hasVirtualEntry = false;
    if (napi_has_named_property(env, fileUri, "virtualEntry", &hasVirtualEntry) != napi_ok) {
        return false;
    }
    if (!hasVirtualEntry) {
        return true;
    }
    napi_value provider = nullptr;
    napi_value root = nullptr;
    VirtualEntry itemInfo;
    uint32_t itemCount = 0;
    bool hasOnStat = false;
    if (napi_get_named_property(env, fileUri, "virtualEntry", &provider) != napi_ok) {
        return false;
    }
    if (NapiDataUtils::IsUndefinedOrNull(env, provider)) {
        return true;
    }
    return IsVirtualEntryProvider(env, provider, hasOnStat) && GetNamedProperty(env, provider, "itemInfo", root) &&
           ParseVirtualItem(env, root, itemInfo, 0, itemCount) && (!NeedsStatCallback(itemInfo) || hasOnStat) &&
           VirtualEntryNapiRegistry::GetInstance().Put(file, env, provider, std::move(itemInfo));
}

napi_value FileNapi::Constructor(napi_env env)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    napi_property_descriptor properties[] = {
        /* File extends UnifiedRecord */
        DECLARE_NAPI_FUNCTION("getType", UnifiedRecordNapi::GetType),
        DECLARE_NAPI_FUNCTION("getValue", UnifiedRecordNapi::GetValue),
        DECLARE_NAPI_FUNCTION("addEntry", UnifiedRecordNapi::AddEntry),
        DECLARE_NAPI_FUNCTION("getEntry", UnifiedRecordNapi::GetEntry),
        DECLARE_NAPI_FUNCTION("getEntries", UnifiedRecordNapi::GetEntries),
        DECLARE_NAPI_FUNCTION("getTypes", UnifiedRecordNapi::GetTypes),
        /* File properties */
        DECLARE_NAPI_GETTER_SETTER("details", GetDetails, SetDetails),
        DECLARE_NAPI_GETTER_SETTER("uri", GetUri, SetUri),
        DECLARE_NAPI_GETTER_SETTER("uriAuthorizationPolicies", nullptr, SetUriAuthorizationPolicies),
    };
    size_t count = sizeof(properties) / sizeof(properties[0]);
    return NapiDataUtils::DefineClass(env, "File", properties, count, FileNapi::New);
}

napi_value FileNapi::New(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    auto ctxt = std::make_shared<ContextBase>();
    ctxt->GetCbInfoSync(env, info);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, ctxt->error);

    auto *file = new (std::nothrow) FileNapi();
    ASSERT_ERR(ctxt->env, file != nullptr, Status::E_ERROR, "no memory for file!");
    file->value_ = std::make_shared<File>();
    ASSERT_CALL(env, napi_wrap(env, ctxt->self, file, Destructor, nullptr, nullptr), file);
    return ctxt->self;
}

void FileNapi::NewInstance(napi_env env, std::shared_ptr<UnifiedRecord> in, napi_value &out)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    ASSERT_CALL_VOID(env, napi_new_instance(env, Constructor(env), 0, nullptr, &out));
    FileNapi *file = nullptr;
    ASSERT_CALL_VOID(env, napi_unwrap(env, out, reinterpret_cast<void **>(&file)));
    ASSERT_ERR_VOID(env, file != nullptr, Status::E_ERROR, "unwrap file failed!");
    file->value_ = std::static_pointer_cast<File>(in);
}

void FileNapi::Destructor(napi_env env, void *data, void *hint)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi finalize.");
    auto *file = static_cast<FileNapi *>(data);
    ASSERT_VOID(file != nullptr, "finalize null!");
    delete file;
}

FileNapi *FileNapi::GetFile(napi_env env, napi_callback_info info, std::shared_ptr<ContextBase> ctxt)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    ctxt->GetCbInfoSync(env, info);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, ctxt->error);
    return static_cast<FileNapi *>(ctxt->native);
}

napi_value FileNapi::GetDetails(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    auto ctxt = std::make_shared<ContextBase>();
    auto file = GetFile(env, info, ctxt);
    ASSERT_ERR(ctxt->env, (file != nullptr && file->value_ != nullptr), Status::E_ERROR, "invalid object!");
    ctxt->status = NapiDataUtils::SetValue(env, file->value_->GetDetails(), ctxt->output);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, "set details failed!");
    return ctxt->output;
}

napi_value FileNapi::SetDetails(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    auto ctxt = std::make_shared<ContextBase>();
    UDDetails details;
    auto input = [env, ctxt, &details](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::E_INVALID_PARAMETERS,
            "Parameter error: Mandatory parameters are left unspecified");
        if (!NapiDataUtils::IsUndefinedOrNull(env, argv[0])) {
            ctxt->status = NapiDataUtils::GetValue(env, argv[0], details);
            ASSERT_BUSINESS_ERR(ctxt, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS,
                "Parameter error: parameter details type must be "
                "Record<string, string>");
        }
    };
    ctxt->GetCbInfoSync(env, info, input);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, ctxt->error);
    auto file = static_cast<FileNapi *>(ctxt->native);
    ASSERT_ERR(ctxt->env, (file != nullptr && file->value_ != nullptr), Status::E_ERROR, "invalid object!");
    file->value_->SetDetails(details);
    return nullptr;
}

napi_value FileNapi::GetUri(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    auto ctxt = std::make_shared<ContextBase>();
    auto file = GetFile(env, info, ctxt);
    ASSERT_ERR(ctxt->env, (file != nullptr && file->value_ != nullptr), Status::E_ERROR, "invalid object!");
    ctxt->status = NapiDataUtils::SetValue(env, file->value_->GetUri(), ctxt->output);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, "set uri failed!");
    return ctxt->output;
}

napi_value FileNapi::SetUri(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    auto ctxt = std::make_shared<ContextBase>();
    std::string uri;
    auto input = [env, ctxt, &uri](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::E_INVALID_PARAMETERS,
            "Parameter error: Mandatory parameters are left unspecified");
        ctxt->status = NapiDataUtils::GetValue(env, argv[0], uri);
        ASSERT_BUSINESS_ERR(ctxt, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS,
            "Parameter error: parameter uri type must be string");
    };
    ctxt->GetCbInfoSync(env, info, input);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, ctxt->error);
    auto file = static_cast<FileNapi *>(ctxt->native);
    ASSERT_ERR(ctxt->env, (file != nullptr && file->value_ != nullptr), Status::E_ERROR, "invalid object!");
    file->value_->SetUri(uri);
    return nullptr;
}

napi_value FileNapi::SetUriAuthorizationPolicies(napi_env env, napi_callback_info info)
{
    HISTOGRAM_BOOLEAN("Udmf.APICall.File.uriAuthorizationPolicies", true);
    LOG_DEBUG(UDMF_KITS_NAPI, "FileNapi");
    auto ctxt = std::make_shared<ContextBase>();
    std::vector<int32_t> uriAuthorizationPolicies;
    auto input = [env, ctxt, &uriAuthorizationPolicies](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::E_INVALID_PARAMETERS,
            "Parameter error: Mandatory parameters are left unspecified");
        if (!NapiDataUtils::IsUndefinedOrNull(env, argv[0])) {
            ctxt->status = NapiDataUtils::GetValue(env, argv[0], uriAuthorizationPolicies);
            ASSERT_BUSINESS_ERR(ctxt, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS,
                "Parameter error: parameter uriAuthorizationPolicies "
                "type must be Array<number>");
        }
    };
    ctxt->GetCbInfoSync(env, info, input);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_ERROR, ctxt->error);
    auto file = static_cast<FileNapi *>(ctxt->native);
    ASSERT_ERR(ctxt->env, (file != nullptr && file->value_ != nullptr), Status::E_ERROR, "invalid object!");
    file->value_->SetUriAuthorizationPolicyMask(UriPermissionUtil::ToMask(uriAuthorizationPolicies));
    return nullptr;
}
} // namespace UDMF
} // namespace OHOS

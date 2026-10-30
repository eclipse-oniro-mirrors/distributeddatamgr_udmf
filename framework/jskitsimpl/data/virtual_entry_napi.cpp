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
#define LOG_TAG "VirtualEntryNapi"
#include "virtual_entry_napi.h"

#include <cmath>
#include <limits>

#include "file.h"
#include "napi_data_utils.h"
#include "virtual_entry_provider_napi.h"
#include "virtual_entry_attachment_registry.h"
#include "virtual_file_info_napi.h"

namespace OHOS::UDMF {
namespace {
constexpr size_t REQUIRED_ARGUMENT_COUNT = 2;
constexpr size_t CONSTRUCTOR_ARGUMENT_COUNT = 4;

bool IsType(napi_env env, napi_value value, napi_valuetype expected)
{
    napi_valuetype actual = napi_undefined;
    return value != nullptr && napi_typeof(env, value, &actual) == napi_ok && actual == expected;
}

bool IsOptionalFunction(napi_env env, napi_value value)
{
    return value == nullptr || NapiDataUtils::IsUndefinedOrNull(env, value) || IsType(env, value, napi_function);
}

napi_value ThrowConstructorTypeError(napi_env env, const char *message)
{
    (void)napi_throw_type_error(env, nullptr, message);
    return nullptr;
}

bool SetProperty(napi_env env, napi_value object, const char *name, napi_value value)
{
    return napi_set_named_property(env, object, name, value) == napi_ok;
}
} // namespace

bool ParseVirtualFileSize(napi_env env, napi_value value, int64_t &size)
{
    double number = 0;
    const double upperBound = -static_cast<double>(std::numeric_limits<int64_t>::min());
    if (NapiDataUtils::GetValue(env, value, number) != napi_ok || !std::isfinite(number) || number < 0 ||
        number >= upperBound || std::trunc(number) != number) {
        return false;
    }
    size = static_cast<int64_t>(number);
    return true;
}

napi_value VirtualFileInfoNapi::Constructor(napi_env env)
{
    return NapiDataUtils::DefineClass(env, "VirtualFileInfo", nullptr, 0, New);
}

napi_value VirtualFileInfoNapi::New(napi_env env, napi_callback_info info)
{
    size_t argc = CONSTRUCTOR_ARGUMENT_COUNT;
    napi_value argv[CONSTRUCTOR_ARGUMENT_COUNT] = { nullptr };
    napi_value self = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &self, nullptr) != napi_ok || self == nullptr) {
        return ThrowConstructorTypeError(env, "Failed to obtain constructor parameters");
    }
    if (argc < REQUIRED_ARGUMENT_COUNT) {
        return ThrowConstructorTypeError(env, "itemInfo and onRead are required");
    }
    if (!IsType(env, argv[0], napi_object)) {
        return ThrowConstructorTypeError(env, "itemInfo must be an object");
    }
    if (!IsType(env, argv[1], napi_function)) {
        return ThrowConstructorTypeError(env, "onRead must be a function");
    }
    if (!IsOptionalFunction(env, argv[2])) {
        return ThrowConstructorTypeError(env, "onStat must be a function");
    }
    if (!IsOptionalFunction(env, argv[3])) {
        return ThrowConstructorTypeError(env, "onCancel must be a function");
    }
    if (!SetProperty(env, self, "itemInfo", argv[0]) || !SetProperty(env, self, "onRead", argv[1])) {
        return ThrowConstructorTypeError(env, "Failed to initialize VirtualFileInfo");
    }
    if (argv[2] != nullptr && !NapiDataUtils::IsUndefinedOrNull(env, argv[2]) &&
        !SetProperty(env, self, "onStat", argv[2])) {
        return ThrowConstructorTypeError(env, "Failed to initialize onStat");
    }
    if (argv[3] != nullptr && !NapiDataUtils::IsUndefinedOrNull(env, argv[3]) &&
        !SetProperty(env, self, "onCancel", argv[3])) {
        return ThrowConstructorTypeError(env, "Failed to initialize onCancel");
    }
    return self;
}

VirtualEntryNapiRegistry &VirtualEntryNapiRegistry::GetInstance()
{
    static VirtualEntryNapiRegistry registry;
    return registry;
}

bool VirtualEntryNapiRegistry::Put(
    const std::shared_ptr<File> &file, napi_env env, napi_value provider, VirtualEntry itemInfo)
{
    if (file == nullptr || env == nullptr || provider == nullptr) {
        return false;
    }
    auto providerStub = VirtualEntryProviderNapi::Create(env, provider);
    if (providerStub == nullptr) {
        return false;
    }
    bool addCleanupHook = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        addCleanupHook = environments_.emplace(env).second;
    }
    if (addCleanupHook && napi_add_env_cleanup_hook(env, CleanupEnv, env) != napi_ok) {
        std::lock_guard<std::mutex> lock(mutex_);
        environments_.erase(env);
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (environments_.find(env) == environments_.end()) {
        return false;
    }
    return VirtualEntryAttachmentRegistry::Attach(file, itemInfo, providerStub->AsObject(), env);
}

void VirtualEntryNapiRegistry::CleanupEnv(void *data)
{
    GetInstance().RemoveEnv(static_cast<napi_env>(data));
}

void VirtualEntryNapiRegistry::RemoveEnv(napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    environments_.erase(env);
    VirtualEntryAttachmentRegistry::Detach(env);
}
} // namespace OHOS::UDMF

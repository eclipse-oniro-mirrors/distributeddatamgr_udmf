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

namespace OHOS::UDMF {
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

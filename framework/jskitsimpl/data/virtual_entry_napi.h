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

#ifndef UDMF_VIRTUAL_ENTRY_NAPI_H
#define UDMF_VIRTUAL_ENTRY_NAPI_H

#include <memory>
#include <mutex>
#include <unordered_set>

#include "napi/native_api.h"
#include "virtual_entry.h"

namespace OHOS::UDMF {
class File;

class VirtualEntryNapiRegistry final {
public:
    static VirtualEntryNapiRegistry &GetInstance();

    bool Put(const std::shared_ptr<File> &file, napi_env env, napi_value provider, VirtualEntry itemInfo);

private:
    VirtualEntryNapiRegistry() = default;
    static void CleanupEnv(void *data);
    void RemoveEnv(napi_env env);

    std::mutex mutex_;
    std::unordered_set<napi_env> environments_;
};
} // namespace OHOS::UDMF

#endif // UDMF_VIRTUAL_ENTRY_NAPI_H

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

#ifndef UDMF_VIRTUAL_ENTRY_PROVIDER_NAPI_H
#define UDMF_VIRTUAL_ENTRY_PROVIDER_NAPI_H

#include <condition_variable>
#include <memory>
#include <mutex>

#include "iremote_stub.h"
#include "napi/native_api.h"
#include "virtual_entry_provider.h"
#include "virtual_entry_request_coordinator.h"

namespace OHOS::UDMF {
class VirtualEntryProviderNapi final : public IRemoteStub<IVirtualEntryProvider> {
public:
    static sptr<VirtualEntryProviderNapi> Create(napi_env env, napi_value provider);
    ~VirtualEntryProviderNapi() override;

    int32_t Stat(const std::string &id, VirtualEntry &entry) override;
    int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) override;
    int32_t Cancel(const std::vector<std::string> &ids) override;
    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override;

private:
    enum class Operation : uint8_t { STAT, READ, CANCEL };
    struct Request;
    struct TsfnContext;
    struct PromiseToken;

    explicit VirtualEntryProviderNapi(napi_threadsafe_function tsfn) : tsfn_(tsfn)
    {
    }
    int32_t Enqueue(const std::shared_ptr<Request> &request, napi_threadsafe_function_call_mode mode);
    int32_t Invoke(const std::shared_ptr<Request> &request);
    void QueueCancel(const std::string &id);
    static void FailRequest(const std::shared_ptr<Request> &request, int32_t status);
    static const char *GetCallbackName(Operation operation);
    static bool BuildArguments(
        napi_env env, const std::shared_ptr<Request> &request, napi_value *arguments, size_t &argumentCount);
    static bool AttachPromiseHandlers(
        napi_env env, napi_value promise, const std::shared_ptr<Request> &request);
    static void CallJs(napi_env env, napi_value callback, void *context, void *data);
    static napi_value PromiseResolved(napi_env env, napi_callback_info info);
    static napi_value PromiseRejected(napi_env env, napi_callback_info info);
    static void PromiseTokenFinalizer(napi_env env, void *data, void *hint);
    static void TsfnFinalizer(napi_env env, void *data, void *hint);
    static bool Complete(napi_env env, const std::shared_ptr<Request> &request, napi_value value);

    napi_threadsafe_function tsfn_{ nullptr };
    static VirtualEntryRequestCoordinator requestCoordinator_;
};
} // namespace OHOS::UDMF

#endif // UDMF_VIRTUAL_ENTRY_PROVIDER_NAPI_H

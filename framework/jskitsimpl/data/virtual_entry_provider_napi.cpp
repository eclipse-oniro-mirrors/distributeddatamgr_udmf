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
#define LOG_TAG "VirtualEntryProviderNapi"
#include "virtual_entry_provider_napi.h"

#include <cerrno>
#include <cinttypes>
#include <new>
#include <utility>

#include "ashmem.h"
#include "ipc_skeleton.h"
#include "logger.h"
#include "napi_data_utils.h"
#include "udmf_utils.h"
#include "virtual_entry_napi.h"
#include "virtual_entry_read_callback_proxy.h"

namespace OHOS::UDMF {
namespace {
constexpr int32_t PROVIDER_BLOCK_BYTES = 5 * 1024 * 1024;
constexpr char VIRTUAL_ENTRY_ASHMEM_NAME[] = "UdmfVirtualEntry";
constexpr size_t MAX_CALLBACK_ARGUMENT_COUNT = 3;
constexpr size_t PROMISE_HANDLER_COUNT = 2;
constexpr size_t ID_ARGUMENT_INDEX = 0;
constexpr size_t OFFSET_ARGUMENT_INDEX = 1;
constexpr size_t LENGTH_ARGUMENT_INDEX = 2;
constexpr size_t SINGLE_ARGUMENT_COUNT = 1;
constexpr size_t READ_ARGUMENT_COUNT = 3;

bool GetFunction(napi_env env, napi_value provider, const char *name, napi_value &function)
{
    napi_valuetype type = napi_undefined;
    return napi_get_named_property(env, provider, name, &function) == napi_ok &&
           napi_typeof(env, function, &type) == napi_ok && type == napi_function;
}

bool ParseStat(napi_env env, napi_value value, VirtualEntry &entry)
{
    napi_value field = nullptr;
    std::string type;
    if (napi_get_named_property(env, value, "id", &field) != napi_ok ||
        NapiDataUtils::GetValue(env, field, entry.id) != napi_ok ||
        napi_get_named_property(env, value, "name", &field) != napi_ok ||
        NapiDataUtils::GetValue(env, field, entry.name) != napi_ok ||
        napi_get_named_property(env, value, "type", &field) != napi_ok ||
        NapiDataUtils::GetValue(env, field, type) != napi_ok || type != "file" ||
        napi_get_named_property(env, value, "modifyTime", &field) != napi_ok ||
        NapiDataUtils::GetValue(env, field, entry.modifyTime) != napi_ok) {
        return false;
    }
    entry.type = VirtualEntryType::FILE;
    if (napi_get_named_property(env, value, "size", &field) != napi_ok) {
        return false;
    }
    return ParseVirtualFileSize(env, field, entry.size);
}
} // namespace

struct VirtualEntryProviderNapi::Request {
    Operation operation{ Operation::READ };
    std::string id;
    int64_t offset{ 0 };
    int32_t length{ 0 };
    std::vector<std::string> ids;
    VirtualEntry entry;
    std::vector<uint8_t> bytes;
    std::mutex mutex;
    std::condition_variable condition;
    bool done{ false };
    int32_t status{ -EIO };
};

struct VirtualEntryProviderNapi::TsfnContext {
    napi_ref providerRef{ nullptr };
};

struct VirtualEntryProviderNapi::PromiseToken {
    std::shared_ptr<Request> request;
};

VirtualEntryRequestCoordinator VirtualEntryProviderNapi::requestCoordinator_;

sptr<VirtualEntryProviderNapi> VirtualEntryProviderNapi::Create(napi_env env, napi_value provider)
{
    auto *context = new (std::nothrow) TsfnContext();
    if (context == nullptr || napi_create_reference(env, provider, 1, &context->providerRef) != napi_ok) {
        delete context;
        return nullptr;
    }
    napi_value name = nullptr;
    napi_threadsafe_function tsfn = nullptr;
    if (napi_create_string_utf8(env, "UdmfVirtualEntryProvider", NAPI_AUTO_LENGTH, &name) != napi_ok ||
        napi_create_threadsafe_function(
            env, nullptr, nullptr, name, 0, 1, context, TsfnFinalizer, context, CallJs, &tsfn) != napi_ok) {
        napi_delete_reference(env, context->providerRef);
        delete context;
        return nullptr;
    }
    return new (std::nothrow) VirtualEntryProviderNapi(tsfn);
}

VirtualEntryProviderNapi::~VirtualEntryProviderNapi()
{
    if (tsfn_ != nullptr) {
        napi_release_threadsafe_function(tsfn_, napi_tsfn_abort);
    }
}

int32_t VirtualEntryProviderNapi::Enqueue(
    const std::shared_ptr<Request> &request, napi_threadsafe_function_call_mode mode)
{
    auto *holder = new (std::nothrow) PromiseToken{ request };
    if (holder == nullptr) {
        return -ENOMEM;
    }
    napi_status status = napi_call_threadsafe_function(tsfn_, holder, mode);
    if (status != napi_ok) {
        LOG_ERROR(UDMF_KITS_NAPI,
            "Enqueue virtual entry callback failed, operation=%{public}u, napiStatus=%{public}d",
            static_cast<uint32_t>(request->operation), status);
        delete holder;
        return -EIO;
    }
    return 0;
}

int32_t VirtualEntryProviderNapi::Invoke(const std::shared_ptr<Request> &request)
{
    int32_t ret = Enqueue(request, napi_tsfn_blocking);
    if (ret != 0) {
        return ret;
    }
    std::unique_lock<std::mutex> lock(request->mutex);
    if (!requestCoordinator_.Wait(request->condition, lock, [&request] { return request->done; })) {
        request->done = true;
        request->status = -ETIMEDOUT;
        lock.unlock();
        if (request->operation == Operation::READ) {
            QueueCancel(request->id);
        }
        LOG_WARN(UDMF_KITS_NAPI, "Virtual entry provider callback timed out, operation=%{public}u",
            static_cast<uint32_t>(request->operation));
        return -ETIMEDOUT;
    }
    return request->status;
}

void VirtualEntryProviderNapi::QueueCancel(const std::string &id)
{
    if (Cancel({ id }) != 0) {
        LOG_ERROR(UDMF_KITS_NAPI, "Queue virtual entry cancel request failed");
    }
}

void VirtualEntryProviderNapi::FailRequest(const std::shared_ptr<Request> &request, int32_t status)
{
    std::lock_guard<std::mutex> lock(request->mutex);
    request->done = true;
    request->status = status;
    request->condition.notify_all();
}

const char *VirtualEntryProviderNapi::GetCallbackName(Operation operation)
{
    switch (operation) {
        case Operation::STAT:
            return "onStat";
        case Operation::READ:
            return "onRead";
        case Operation::CANCEL:
            return "onCancel";
        default:
            return "";
    }
}

bool VirtualEntryProviderNapi::BuildArguments(
    napi_env env, const std::shared_ptr<Request> &request, napi_value *arguments, size_t &argumentCount)
{
    if (request->operation == Operation::CANCEL) {
        if (napi_create_array_with_length(env, request->ids.size(), &arguments[ID_ARGUMENT_INDEX]) != napi_ok) {
            return false;
        }
        for (uint32_t index = 0; index < request->ids.size(); ++index) {
            napi_value id = nullptr;
            if (NapiDataUtils::SetValue(env, request->ids[index], id) != napi_ok ||
                napi_set_element(env, arguments[ID_ARGUMENT_INDEX], index, id) != napi_ok) {
                return false;
            }
        }
        argumentCount = SINGLE_ARGUMENT_COUNT;
        return true;
    }
    if (NapiDataUtils::SetValue(env, request->id, arguments[ID_ARGUMENT_INDEX]) != napi_ok) {
        return false;
    }
    argumentCount = SINGLE_ARGUMENT_COUNT;
    if (request->operation == Operation::READ) {
        if (NapiDataUtils::SetValue(env, request->offset, arguments[OFFSET_ARGUMENT_INDEX]) != napi_ok ||
            NapiDataUtils::SetValue(env, request->length, arguments[LENGTH_ARGUMENT_INDEX]) != napi_ok) {
            return false;
        }
        argumentCount = READ_ARGUMENT_COUNT;
    }
    return true;
}

bool VirtualEntryProviderNapi::AttachPromiseHandlers(
    napi_env env, napi_value promise, const std::shared_ptr<Request> &request)
{
    napi_value thenFunction = nullptr;
    napi_value resolved = nullptr;
    napi_value rejected = nullptr;
    auto *resolvedToken = new (std::nothrow) PromiseToken{ request };
    auto *rejectedToken = new (std::nothrow) PromiseToken{ request };
    if (resolvedToken == nullptr || rejectedToken == nullptr) {
        delete resolvedToken;
        delete rejectedToken;
        return false;
    }
    napi_status status = napi_get_named_property(env, promise, "then", &thenFunction);
    if (status == napi_ok) {
        status = napi_create_function(env, "resolveVirtualEntry", NAPI_AUTO_LENGTH, PromiseResolved,
            resolvedToken, &resolved);
    }
    if (status == napi_ok) {
        status = napi_create_function(env, "rejectVirtualEntry", NAPI_AUTO_LENGTH, PromiseRejected,
            rejectedToken, &rejected);
    }
    if (status != napi_ok) {
        delete resolvedToken;
        delete rejectedToken;
        return false;
    }
    napi_add_finalizer(env, resolved, resolvedToken, PromiseTokenFinalizer, nullptr, nullptr);
    napi_add_finalizer(env, rejected, rejectedToken, PromiseTokenFinalizer, nullptr, nullptr);
    napi_value handlers[] = { resolved, rejected };
    return napi_call_function(env, promise, thenFunction, PROMISE_HANDLER_COUNT, handlers, nullptr) == napi_ok;
}

int32_t VirtualEntryProviderNapi::Stat(const std::string &id, VirtualEntry &entry)
{
    auto request = std::make_shared<Request>();
    request->operation = Operation::STAT;
    request->id = id;
    int32_t ret = Invoke(request);
    if (ret == 0) {
        entry = std::move(request->entry);
    }
    return ret;
}

int32_t VirtualEntryProviderNapi::Read(
    const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data)
{
    if (offset < 0 || length < 0 || length > PROVIDER_BLOCK_BYTES) {
        return -EINVAL;
    }
    if (!requestCoordinator_.TryAcquire()) {
        LOG_WARN(UDMF_KITS_NAPI, "Too many concurrent virtual entry reads");
        return -EAGAIN;
    }
    auto request = std::make_shared<Request>();
    request->operation = Operation::READ;
    request->id = id;
    request->offset = offset;
    request->length = length;
    int32_t ret = Invoke(request);
    requestCoordinator_.Release();
    if (ret == 0) {
        data = std::move(request->bytes);
    }
    return ret;
}

int32_t VirtualEntryProviderNapi::Cancel(const std::vector<std::string> &ids)
{
    if (ids.empty()) {
        return 0;
    }
    auto request = std::make_shared<Request>();
    request->operation = Operation::CANCEL;
    request->ids = ids;
    return Enqueue(request, napi_tsfn_nonblocking);
}

void VirtualEntryProviderNapi::CallJs(napi_env env, napi_value callback, void *context, void *data)
{
    (void)callback;
    std::unique_ptr<PromiseToken> holder(static_cast<PromiseToken *>(data));
    auto request = holder->request;
    if (env == nullptr) {
        LOG_ERROR(UDMF_KITS_NAPI, "Virtual entry callback environment is unavailable, operation=%{public}u",
            static_cast<uint32_t>(request->operation));
        FailRequest(request, -ECANCELED);
        return;
    }
    auto *tsfnContext = static_cast<TsfnContext *>(context);
    napi_value provider = nullptr;
    napi_value function = nullptr;
    const char *name = GetCallbackName(request->operation);
    if (napi_get_reference_value(env, tsfnContext->providerRef, &provider) != napi_ok) {
        LOG_ERROR(UDMF_KITS_NAPI, "Get virtual entry provider reference failed, operation=%{public}u",
            static_cast<uint32_t>(request->operation));
        FailRequest(request, -EIO);
        return;
    }
    if (request->operation == Operation::CANCEL &&
        napi_get_named_property(env, provider, name, &function) == napi_ok &&
        NapiDataUtils::IsUndefinedOrNull(env, function)) {
        FailRequest(request, 0);
        return;
    }
    if (!GetFunction(env, provider, name, function)) {
        LOG_ERROR(UDMF_KITS_NAPI, "Get virtual entry callback failed, operation=%{public}u",
            static_cast<uint32_t>(request->operation));
        int32_t status = request->operation == Operation::STAT ? -ENOSYS : -EIO;
        FailRequest(request, status);
        return;
    }
    InvokeCallback(env, provider, function, request);
}

void VirtualEntryProviderNapi::InvokeCallback(napi_env env, napi_value provider, napi_value function,
    const std::shared_ptr<Request> &request)
{
    napi_value arguments[MAX_CALLBACK_ARGUMENT_COUNT] = { nullptr };
    size_t argumentCount = 0;
    if (!BuildArguments(env, request, arguments, argumentCount)) {
        LOG_ERROR(UDMF_KITS_NAPI, "Build virtual entry callback arguments failed, operation=%{public}u",
            static_cast<uint32_t>(request->operation));
        Complete(env, request, nullptr);
        return;
    }
    napi_value result = nullptr;
    bool isPromise = false;
    napi_status status = napi_call_function(env, provider, function, argumentCount, arguments, &result);
    if (status != napi_ok || result == nullptr) {
        LOG_ERROR(UDMF_KITS_NAPI,
            "Invoke virtual entry callback failed, operation=%{public}u, napiStatus=%{public}d",
            static_cast<uint32_t>(request->operation), status);
        Complete(env, request, nullptr);
        return;
    }
    status = napi_is_promise(env, result, &isPromise);
    if (status != napi_ok) {
        LOG_ERROR(UDMF_KITS_NAPI,
            "Check virtual entry callback result failed, operation=%{public}u, napiStatus=%{public}d",
            static_cast<uint32_t>(request->operation), status);
        Complete(env, request, nullptr);
        return;
    }
    if (!isPromise) {
        Complete(env, request, result);
        return;
    }
    if (!AttachPromiseHandlers(env, result, request)) {
        LOG_ERROR(UDMF_KITS_NAPI, "Attach virtual entry promise handlers failed, operation=%{public}u",
            static_cast<uint32_t>(request->operation));
        Complete(env, request, nullptr);
    }
}

bool VirtualEntryProviderNapi::Complete(napi_env env, const std::shared_ptr<Request> &request, napi_value value)
{
    int32_t status = 0;
    if (value == nullptr) {
        status = -EIO;
    } else if (request->operation == Operation::STAT) {
        status = ParseStat(env, value, request->entry) ? 0 : -EINVAL;
    } else if (request->operation == Operation::READ) {
        napi_typedarray_type type;
        size_t length = 0;
        void *bytes = nullptr;
        napi_value buffer = nullptr;
        size_t offset = 0;
        if (napi_get_typedarray_info(env, value, &type, &length, &bytes, &buffer, &offset) != napi_ok ||
            type != napi_uint8_array || length > static_cast<size_t>(request->length)) {
            LOG_ERROR(UDMF_KITS_NAPI, "Invalid virtual entry read result, requested=%{public}d",
                request->length);
            status = -EINVAL;
        } else {
            auto *begin = static_cast<uint8_t *>(bytes);
            if (length == 0) {
                request->bytes.clear();
            } else {
                request->bytes.assign(begin, begin + length);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(request->mutex);
        if (request->done) {
            return false;
        }
        request->done = true;
        request->status = status;
    }
    request->condition.notify_all();
    return status == 0;
}

napi_value VirtualEntryProviderNapi::PromiseResolved(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { nullptr };
    PromiseToken *token = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, reinterpret_cast<void **>(&token));
    if (token != nullptr) {
        Complete(env, token->request, argc == 1 ? argv[0] : nullptr);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value VirtualEntryProviderNapi::PromiseRejected(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    PromiseToken *token = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, reinterpret_cast<void **>(&token));
    if (token != nullptr) {
        LOG_ERROR(UDMF_KITS_NAPI, "Virtual entry callback promise rejected, operation=%{public}u",
            static_cast<uint32_t>(token->request->operation));
        Complete(env, token->request, nullptr);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

void VirtualEntryProviderNapi::PromiseTokenFinalizer(napi_env env, void *data, void *hint)
{
    (void)env;
    (void)hint;
    delete static_cast<PromiseToken *>(data);
}

void VirtualEntryProviderNapi::TsfnFinalizer(napi_env env, void *data, void *hint)
{
    (void)hint;
    auto *context = static_cast<TsfnContext *>(data);
    if (context != nullptr) {
        napi_delete_reference(env, context->providerRef);
        delete context;
    }
}

int32_t VirtualEntryProviderNapi::OnRemoteRequest(
    uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option)
{
    if (!UTILS::IsNativeCallingToken() || request.ReadInterfaceToken() != GetDescriptor()) {
        LOG_ERROR(UDMF_KITS_NAPI, "Reject virtual entry provider request, code=%{public}u", code);
        return -EACCES;
    }
    switch (code) {
        case static_cast<uint32_t>(VirtualEntryProviderCode::STAT):
            return HandleStatRequest(request, reply);
        case static_cast<uint32_t>(VirtualEntryProviderCode::READ):
            return HandleReadRequest(request, reply);
        case static_cast<uint32_t>(VirtualEntryProviderCode::READ_ASYNC):
            return HandleAsyncReadRequest(request);
        case static_cast<uint32_t>(VirtualEntryProviderCode::CANCEL):
            return HandleCancelRequest(request, reply);
        default:
            return IRemoteStub<IVirtualEntryProvider>::OnRemoteRequest(code, request, reply, option);
    }
}

int32_t VirtualEntryProviderNapi::HandleStatRequest(MessageParcel &request, MessageParcel &reply)
{
    VirtualEntry entry;
    int32_t ret = Stat(request.ReadString(), entry);
    bool writeFailed = !reply.WriteInt32(ret);
    if (ret == 0) {
        writeFailed = writeFailed || !reply.WriteString(entry.id) || !reply.WriteString(entry.name) ||
            !reply.WriteInt32(static_cast<int32_t>(entry.type)) || !reply.WriteInt64(entry.modifyTime) ||
            !reply.WriteInt64(entry.size);
    }
    if (writeFailed) {
        return -EIO;
    }
    return 0;
}

int32_t VirtualEntryProviderNapi::HandleReadRequest(MessageParcel &request, MessageParcel &reply)
{
    std::string id = request.ReadString();
    int64_t offset = request.ReadInt64();
    int32_t length = request.ReadInt32();
    std::vector<uint8_t> bytes;
    int32_t ret = Read(id, offset, length, bytes);
    if (ret != 0) {
        LOG_ERROR(UDMF_KITS_NAPI,
            "Virtual entry read request failed, offset=%{public}" PRId64 ", length=%{public}d, ret=%{public}d",
            offset, length, ret);
    }
    if (!reply.WriteInt32(ret) || !reply.WriteUint32(bytes.size())) {
        return -EIO;
    }
    if (ret != 0 || bytes.empty()) {
        return 0;
    }
    sptr<Ashmem> memory = Ashmem::CreateAshmem(VIRTUAL_ENTRY_ASHMEM_NAME, static_cast<int32_t>(bytes.size()));
    if (memory == nullptr || !memory->MapReadAndWriteAshmem()) {
        return -ENOMEM;
    }
    bool written = memory->WriteToAshmem(bytes.data(), bytes.size(), 0);
    memory->UnmapAshmem();
    if (!written || !reply.WriteAshmem(memory)) {
        memory->CloseAshmem();
        return -EIO;
    }
    return 0;
}

int32_t VirtualEntryProviderNapi::HandleAsyncReadRequest(MessageParcel &request)
{
    std::string id;
    int64_t offset = 0;
    int32_t length = 0;
    sptr<IRemoteObject> callback;
    if (!request.ReadString(id) || !request.ReadInt64(offset) || !request.ReadInt32(length) ||
        (callback = request.ReadRemoteObject()) == nullptr) {
        return -EINVAL;
    }
    std::vector<uint8_t> bytes;
    int32_t ret = Read(id, offset, length, bytes);
    VirtualEntryReadCallbackProxy callbackProxy(callback);
    return callbackProxy.OnResult(ret, bytes);
}

int32_t VirtualEntryProviderNapi::HandleCancelRequest(MessageParcel &request, MessageParcel &reply)
{
    std::vector<std::string> ids;
    int32_t ret = (request.ReadStringVector(&ids) && !ids.empty()) ? Cancel(ids) : -EINVAL;
    return reply.WriteInt32(ret) ? 0 : -EIO;
}
} // namespace OHOS::UDMF

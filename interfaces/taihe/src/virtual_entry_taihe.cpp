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

#define LOG_TAG "UDMF_VIRTUAL_ENTRY_TAIHE"
#include "virtual_entry_taihe.h"

#include <cerrno>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>

#include "ani_common_utils.h"
#include "ashmem.h"
#include "file.h"
#include "iremote_stub.h"
#include "concurrency_helpers.h"
#include "logger.h"
#include "message_option.h"
#include "message_parcel.h"
#include "udmf_utils.h"
#include "virtual_entry.h"
#include "virtual_entry_attachment_registry.h"
#include "virtual_entry_provider.h"
#include "virtual_entry_request_coordinator.h"
#include "virtual_entry_read_callback_proxy.h"

namespace OHOS::UDMF {
namespace {
constexpr uint32_t MAX_VIRTUAL_ENTRY_DEPTH = 64;
constexpr uint32_t MAX_VIRTUAL_ENTRY_COUNT = 4096;
constexpr size_t MAX_VIRTUAL_ENTRY_NAME_BYTES = 255;
constexpr size_t MAX_VIRTUAL_ENTRY_ID_BYTES = 1024;
constexpr int32_t PROVIDER_BLOCK_BYTES = 5 * 1024 * 1024;
constexpr char VIRTUAL_ENTRY_ASHMEM_NAME[] = "UdmfVirtualEntry";
constexpr char UNIFORM_DATA_STRUCT_NAMESPACE[] = "@ohos.data.uniformDataStruct.uniformDataStruct";

class ScopedAniEnv final {
public:
    explicit ScopedAniEnv(ani_vm *vm) : vm_(vm)
    {
        if (vm_ == nullptr) {
            return;
        }
        if (vm_->GetEnv(ANI_VERSION_1, &env_) == ANI_OK) {
            return;
        }
        ani_options options{ 0, nullptr };
        attached_ = vm_->AttachCurrentThread(&options, ANI_VERSION_1, &env_) == ANI_OK;
        if (!attached_) {
            env_ = nullptr;
        }
    }

    ~ScopedAniEnv()
    {
        if (attached_ && vm_ != nullptr) {
            vm_->DetachCurrentThread();
        }
    }

    ani_env *Get() const
    {
        return env_;
    }

private:
    ani_vm *vm_ = nullptr;
    ani_env *env_ = nullptr;
    bool attached_ = false;
};

bool GetProperty(ani_env *env, ani_object object, const char *name, ani_ref &value)
{
    return env->Object_GetPropertyByName_Ref(object, name, &value) == ANI_OK;
}

bool GetStringProperty(ani_env *env, ani_object object, const char *name, std::string &value)
{
    ani_ref property = nullptr;
    return GetProperty(env, object, name, property) &&
           GetString(env, static_cast<ani_object>(property), value) == ANI_OK;
}

bool IsValidName(const std::string &name)
{
    return !name.empty() && name.size() <= MAX_VIRTUAL_ENTRY_NAME_BYTES && name != "." && name != ".." &&
           name.find_first_of("/\\") == std::string::npos && name.find('\0') == std::string::npos;
}

bool IsValidId(const std::string &id)
{
    return !id.empty() && id.size() <= MAX_VIRTUAL_ENTRY_ID_BYTES;
}

bool ParseVirtualItem(ani_env *env, ani_object object, VirtualEntry &entry, uint32_t depth, uint32_t &itemCount);

bool ParseVirtualFile(ani_env *env, ani_object object, VirtualEntry &entry)
{
    entry.type = VirtualEntryType::FILE;
    if (!GetStringProperty(env, object, "id", entry.id) || !IsValidId(entry.id)) {
        return false;
    }
    return env->Object_GetPropertyByName_Long(object, "size", &entry.size) == ANI_OK && entry.size >= 0;
}

bool ParseVirtualDirectory(ani_env *env, ani_object object, VirtualEntry &entry, uint32_t depth, uint32_t &itemCount)
{
    entry.type = VirtualEntryType::DIRECTORY;
    ani_ref subItems = nullptr;
    if (!GetProperty(env, object, "subItems", subItems) || IsNullOrUndefined(env, static_cast<ani_object>(subItems))) {
        return true;
    }
    auto array = static_cast<ani_array>(subItems);
    ani_size length = 0;
    if (env->Array_GetLength(array, &length) != ANI_OK || length > MAX_VIRTUAL_ENTRY_COUNT - itemCount) {
        return false;
    }
    entry.subItems.reserve(length);
    for (ani_size index = 0; index < length; ++index) {
        ani_ref item = nullptr;
        VirtualEntry child;
        if (env->Array_Get(array, index, &item) != ANI_OK ||
            !ParseVirtualItem(env, static_cast<ani_object>(item), child, depth + 1, itemCount)) {
            return false;
        }
        entry.subItems.emplace_back(std::move(child));
    }
    return true;
}

bool ParseVirtualItem(ani_env *env, ani_object object, VirtualEntry &entry, uint32_t depth, uint32_t &itemCount)
{
    if (env == nullptr || object == nullptr || depth > MAX_VIRTUAL_ENTRY_DEPTH ||
        itemCount >= MAX_VIRTUAL_ENTRY_COUNT) {
        return false;
    }
    ++itemCount;
    std::string type;
    if (!GetStringProperty(env, object, "name", entry.name) || !IsValidName(entry.name) ||
        !GetStringProperty(env, object, "type", type) ||
        env->Object_GetPropertyByName_Long(object, "modifyTime", &entry.modifyTime) != ANI_OK) {
        return false;
    }
    if (type == "file") {
        return ParseVirtualFile(env, object, entry);
    }
    return type == "dir" && ParseVirtualDirectory(env, object, entry, depth, itemCount);
}

bool HasCallback(ani_env *env, ani_object provider, const char *name)
{
    ani_ref callback = nullptr;
    return GetProperty(env, provider, name, callback) && !IsNullOrUndefined(env, static_cast<ani_object>(callback));
}

class VirtualEntryProviderTaihe final : public IRemoteStub<IVirtualEntryProvider> {
public:
    static sptr<VirtualEntryProviderTaihe> Create(ani_env *env, ani_object provider)
    {
        if (env == nullptr || provider == nullptr || !HasCallback(env, provider, "onRead") ||
            !HasCallback(env, provider, "onCancel")) {
            return nullptr;
        }
        ani_vm *vm = nullptr;
        ani_ref providerRef = nullptr;
        if (env->GetVM(&vm) != ANI_OK || vm == nullptr ||
            env->GlobalReference_Create(provider, &providerRef) != ANI_OK) {
            return nullptr;
        }
        auto workerId = arkts::concurrency_helpers::GetWorkerId(env);
        if (workerId < 0) {
            env->GlobalReference_Delete(providerRef);
            LOG_ERROR(UDMF_ANI, "Get virtual entry provider worker id failed");
            return nullptr;
        }
        auto *providerStub = new (std::nothrow) VirtualEntryProviderTaihe(vm, providerRef, workerId);
        if (providerStub == nullptr) {
            env->GlobalReference_Delete(providerRef);
        }
        return providerStub;
    }

    ~VirtualEntryProviderTaihe() override
    {
        ScopedAniEnv scopedEnv(vm_);
        ani_env *env = scopedEnv.Get();
        if (env != nullptr && providerRef_ != nullptr) {
            env->GlobalReference_Delete(providerRef_);
        }
    }

    int32_t Stat(const std::string &id, VirtualEntry &entry) override
    {
        if (!IsValidId(id)) {
            return -EINVAL;
        }
        auto request = std::make_shared<Request>();
        request->operation = Operation::STAT;
        request->id = id;
        int32_t ret = Invoke(request);
        if (ret == 0) {
            entry = std::move(request->entry);
        }
        return ret;
    }

    int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) override
    {
        if (!IsValidId(id) || offset < 0 || length < 0 || length > PROVIDER_BLOCK_BYTES) {
            return -EINVAL;
        }
        if (!requestCoordinator_.TryAcquire()) {
            return -EAGAIN;
        }
        auto request = std::make_shared<Request>();
        request->operation = Operation::READ;
        request->id = id;
        request->offset = offset;
        request->length = length;
        int32_t ret = Invoke(request);
        if (ret == 0) {
            data = std::move(request->bytes);
        }
        requestCoordinator_.Release();
        return ret;
    }

    int32_t Cancel(const std::vector<std::string> &ids) override
    {
        if (ids.empty()) {
            return 0;
        }
        if (ids.size() > MAX_VIRTUAL_ENTRY_COUNT) {
            return -EINVAL;
        }
        for (const auto &id : ids) {
            if (!IsValidId(id)) {
                return -EINVAL;
            }
        }
        auto request = std::make_shared<Request>();
        request->operation = Operation::CANCEL;
        request->ids = ids;
        return Invoke(request);
    }

    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override;

private:
    enum class Operation : uint8_t { STAT, READ, CANCEL };

    struct Request {
        Operation operation{ Operation::READ };
        std::string id;
        int64_t offset{ 0 };
        int32_t length{ 0 };
        std::vector<std::string> ids;
        VirtualEntry entry;
        std::vector<uint8_t> bytes;
        ani_vm *vm{ nullptr };
        ani_ref providerRef{ nullptr };
        std::mutex mutex;
        std::condition_variable condition;
        bool done{ false };
        int32_t status{ -EIO };
    };

    struct RequestContext {
        std::shared_ptr<Request> request;
    };

    int32_t HandleStatRequest(MessageParcel &request, MessageParcel &reply);
    int32_t HandleReadRequest(MessageParcel &request, MessageParcel &reply);
    int32_t HandleAsyncReadRequest(MessageParcel &request);
    int32_t HandleCancelRequest(MessageParcel &request, MessageParcel &reply);

    VirtualEntryProviderTaihe(
        ani_vm *vm, ani_ref providerRef, arkts::concurrency_helpers::AniWorkerId workerId)
        : vm_(vm), providerRef_(providerRef), workerId_(workerId)
    {
    }

    static bool FindCallbackFunction(ani_env *env, ani_ref providerRef, const char *callbackName,
        const char *functionName, ani_ref &callback, ani_function &function)
    {
        ani_namespace nameSpace = nullptr;
        return GetProperty(env, static_cast<ani_object>(providerRef), callbackName, callback) &&
               !IsNullOrUndefined(env, static_cast<ani_object>(callback)) &&
               env->FindNamespace(UNIFORM_DATA_STRUCT_NAMESPACE, &nameSpace) == ANI_OK &&
               env->Namespace_FindFunction(nameSpace, functionName, nullptr, &function) == ANI_OK;
    }

    int32_t Invoke(const std::shared_ptr<Request> &request)
    {
        ScopedAniEnv scopedEnv(vm_);
        ani_env *env = scopedEnv.Get();
        if (env == nullptr) {
            LOG_ERROR(UDMF_ANI, "Get ANI environment for virtual entry callback failed");
            return -EIO;
        }
        ani_ref requestProviderRef = nullptr;
        if (env->GlobalReference_Create(static_cast<ani_object>(providerRef_), &requestProviderRef) != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Create virtual entry provider request reference failed");
            return -EIO;
        }
        request->vm = vm_;
        request->providerRef = requestProviderRef;
        auto *holder = new (std::nothrow) RequestContext{ request };
        if (holder == nullptr) {
            env->GlobalReference_Delete(requestProviderRef);
            request->providerRef = nullptr;
            return -ENOMEM;
        }

        auto currentWorkerId = arkts::concurrency_helpers::GetWorkerId(env);
        if (currentWorkerId == workerId_) {
            ExecuteCallback(holder);
        } else if (arkts::concurrency_helpers::SendEvent(env, workerId_, ExecuteCallback, holder) !=
                   arkts::concurrency_helpers::WorkStatus::OK) {
            delete holder;
            env->GlobalReference_Delete(requestProviderRef);
            request->providerRef = nullptr;
            LOG_ERROR(UDMF_ANI, "Dispatch virtual entry callback to ArkTS worker failed");
            return -EIO;
        }

        std::unique_lock<std::mutex> lock(request->mutex);
        if (!requestCoordinator_.Wait(request->condition, lock, [&request] { return request->done; })) {
            request->done = true;
            request->status = -ETIMEDOUT;
            LOG_WARN(UDMF_ANI, "Virtual entry callback timed out, operation=%{public}s",
                GetOperationName(request->operation));
            return -ETIMEDOUT;
        }
        return request->status;
    }

    static void ExecuteCallback(void *data)
    {
        std::unique_ptr<RequestContext> holder(static_cast<RequestContext *>(data));
        auto request = holder->request;
        bool expired = false;
        {
            std::lock_guard<std::mutex> lock(request->mutex);
            expired = request->done;
        }
        if (expired) {
            DeleteRequestReference(request);
            return;
        }
        ScopedAniEnv scopedEnv(request->vm);
        ani_env *env = scopedEnv.Get();
        int32_t status = env == nullptr ? -EIO : ExecuteRequest(env, request);
        DeleteRequestReference(request);
        Complete(request, status);
    }

    static int32_t ExecuteRequest(ani_env *env, const std::shared_ptr<Request> &request)
    {
        switch (request->operation) {
            case Operation::STAT:
                return ExecuteStat(env, request);
            case Operation::READ:
                return ExecuteRead(env, request);
            case Operation::CANCEL:
                return ExecuteCancel(env, request);
            default:
                return -EINVAL;
        }
    }

    static int32_t ExecuteStat(ani_env *env, const std::shared_ptr<Request> &request)
    {
        ani_function function = nullptr;
        ani_ref callback = nullptr;
        ani_string aniId = nullptr;
        ani_ref result = nullptr;
        if (!FindCallbackFunction(env, request->providerRef, "onStat", "virtualFileOnStatFunc", callback, function)) {
            LOG_ERROR(UDMF_ANI, "Find virtual entry stat callback failed");
            return -EIO;
        }
        ani_status status = env->String_NewUTF8(request->id.data(), request->id.size(), &aniId);
        if (status != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Create virtual entry stat id failed, status=%{public}d", status);
            return -EIO;
        }
        status = env->Function_Call_Ref(function, &result, callback, aniId);
        if (status != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Invoke virtual entry stat callback failed, status=%{public}d", status);
            env->ResetError();
            return -EIO;
        }
        uint32_t itemCount = 0;
        if (!ParseVirtualItem(env, static_cast<ani_object>(result), request->entry, 0, itemCount) ||
            request->entry.type != VirtualEntryType::FILE) {
            LOG_ERROR(UDMF_ANI, "Parse virtual entry stat result failed");
            return -EINVAL;
        }
        return 0;
    }

    static int32_t ExecuteRead(ani_env *env, const std::shared_ptr<Request> &request)
    {
        ani_function function = nullptr;
        ani_ref callback = nullptr;
        ani_string aniId = nullptr;
        ani_ref result = nullptr;
        if (!FindCallbackFunction(env, request->providerRef, "onRead", "virtualFileOnReadFunc", callback, function)) {
            LOG_ERROR(UDMF_ANI, "Find virtual entry read callback failed");
            return -EIO;
        }
        ani_status status = env->String_NewUTF8(request->id.data(), request->id.size(), &aniId);
        if (status != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Create virtual entry read id failed, status=%{public}d", status);
            return -EIO;
        }
        status = env->Function_Call_Ref(function, &result, callback, aniId, request->offset, request->length);
        if (status != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Invoke virtual entry read callback failed, status=%{public}d", status);
            env->ResetError();
            return -EIO;
        }
        status = GetUint8Array(env, static_cast<ani_object>(result), request->bytes);
        if (status != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Parse virtual entry read result failed, status=%{public}d", status);
            return -EIO;
        }
        if (request->bytes.size() > static_cast<size_t>(request->length)) {
            LOG_ERROR(UDMF_ANI, "Virtual entry read result exceeds requested length");
            return -EIO;
        }
        return 0;
    }

    static int32_t ExecuteCancel(ani_env *env, const std::shared_ptr<Request> &request)
    {
        ani_function function = nullptr;
        ani_ref callback = nullptr;
        ani_array aniIds = nullptr;
        if (!FindCallbackFunction(
            env, request->providerRef, "onCancel", "virtualFileOnCancelFunc", callback, function)) {
            LOG_ERROR(UDMF_ANI, "Find virtual entry cancel callback failed");
            return -EIO;
        }
        if (!CreateStringArray(env, request->ids, aniIds)) {
            LOG_ERROR(UDMF_ANI, "Create virtual entry cancel id array failed");
            return -EIO;
        }
        ani_status status = env->Function_Call_Void(function, callback, aniIds);
        if (status != ANI_OK) {
            LOG_ERROR(UDMF_ANI, "Invoke virtual entry cancel callback failed, status=%{public}d", status);
            env->ResetError();
            return -EIO;
        }
        return 0;
    }

    static void DeleteRequestReference(const std::shared_ptr<Request> &request)
    {
        if (request->providerRef == nullptr) {
            return;
        }
        ScopedAniEnv scopedEnv(request->vm);
        ani_env *env = scopedEnv.Get();
        if (env != nullptr) {
            env->GlobalReference_Delete(request->providerRef);
        }
        request->providerRef = nullptr;
    }

    static void Complete(const std::shared_ptr<Request> &request, int32_t status)
    {
        std::lock_guard<std::mutex> lock(request->mutex);
        if (request->done) {
            return;
        }
        request->status = status;
        request->done = true;
        request->condition.notify_all();
    }

    static const char *GetOperationName(Operation operation)
    {
        switch (operation) {
            case Operation::STAT:
                return "stat";
            case Operation::READ:
                return "read";
            case Operation::CANCEL:
                return "cancel";
            default:
                return "unknown";
        }
    }

    static bool CreateStringArray(ani_env *env, const std::vector<std::string> &ids, ani_array &result)
    {
        ani_ref initialValue = nullptr;
        if (env->GetUndefined(&initialValue) != ANI_OK || env->Array_New(ids.size(), initialValue, &result) != ANI_OK) {
            return false;
        }
        for (ani_size index = 0; index < ids.size(); ++index) {
            ani_string id = nullptr;
            if (env->String_NewUTF8(ids[index].data(), ids[index].size(), &id) != ANI_OK ||
                env->Array_Set(result, index, id) != ANI_OK) {
                return false;
            }
        }
        return true;
    }

    ani_vm *vm_ = nullptr;
    ani_ref providerRef_ = nullptr;
    arkts::concurrency_helpers::AniWorkerId workerId_{ -1 };
    static VirtualEntryRequestCoordinator requestCoordinator_;
};

VirtualEntryRequestCoordinator VirtualEntryProviderTaihe::requestCoordinator_;

int32_t VirtualEntryProviderTaihe::OnRemoteRequest(
    uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option)
{
    if (!UTILS::IsNativeCallingToken() || request.ReadInterfaceToken() != GetDescriptor()) {
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

int32_t VirtualEntryProviderTaihe::HandleStatRequest(MessageParcel &request, MessageParcel &reply)
{
    VirtualEntry entry;
    int32_t ret = Stat(request.ReadString(), entry);
    bool failed = !reply.WriteInt32(ret);
    if (ret == 0) {
        failed = failed || !reply.WriteString(entry.id) || !reply.WriteString(entry.name) ||
            !reply.WriteInt32(static_cast<int32_t>(entry.type)) || !reply.WriteInt64(entry.modifyTime) ||
            !reply.WriteInt64(entry.size);
    }
    return failed ? -EIO : 0;
}

int32_t VirtualEntryProviderTaihe::HandleReadRequest(MessageParcel &request, MessageParcel &reply)
{
    std::string id = request.ReadString();
    int64_t offset = request.ReadInt64();
    int32_t length = request.ReadInt32();
    std::vector<uint8_t> bytes;
    int32_t ret = Read(id, offset, length, bytes);
    if (!reply.WriteInt32(ret) || !reply.WriteUint32(static_cast<uint32_t>(bytes.size()))) {
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

int32_t VirtualEntryProviderTaihe::HandleAsyncReadRequest(MessageParcel &request)
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

int32_t VirtualEntryProviderTaihe::HandleCancelRequest(MessageParcel &request, MessageParcel &reply)
{
    std::vector<std::string> ids;
    int32_t ret = request.ReadStringVector(&ids) ? Cancel(ids) : -EINVAL;
    return reply.WriteInt32(ret) ? 0 : -EIO;
}
} // namespace

bool VirtualEntryTaihe::Attach(ani_env *env, uintptr_t virtualEntry, const std::shared_ptr<File> &file)
{
    if (env == nullptr || virtualEntry == 0 || file == nullptr) {
        return false;
    }
    auto provider = reinterpret_cast<ani_object>(virtualEntry);
    ani_ref itemInfo = nullptr;
    VirtualEntry entry;
    uint32_t itemCount = 0;
    if (!GetProperty(env, provider, "itemInfo", itemInfo) ||
        !ParseVirtualItem(env, static_cast<ani_object>(itemInfo), entry, 0, itemCount)) {
        return false;
    }
    auto providerStub = VirtualEntryProviderTaihe::Create(env, provider);
    return providerStub != nullptr &&
           VirtualEntryAttachmentRegistry::Attach(file, entry, providerStub->AsObject(), providerStub.GetRefPtr());
}
} // namespace OHOS::UDMF

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

#define LOG_TAG "VirtualEntryNdk"

#include "virtual_entry_capi.h"

#include <atomic>
#include <cerrno>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include "ashmem.h"
#include "file.h"
#include "iremote_stub.h"
#include "logger.h"
#include "message_option.h"
#include "message_parcel.h"
#include "udmf_err_code.h"
#include "udmf_utils.h"
#include "virtual_entry_attachment_registry.h"
#include "virtual_entry_read_callback_proxy.h"

namespace OHOS::UDMF {
namespace {
constexpr uint32_t MAX_VIRTUAL_ENTRY_DEPTH = 64;
constexpr uint32_t MAX_VIRTUAL_ENTRY_COUNT = 4096;
constexpr size_t MAX_VIRTUAL_ENTRY_NAME_BYTES = 255;
constexpr size_t MAX_VIRTUAL_ENTRY_ID_BYTES = 1024;
constexpr int32_t PROVIDER_BLOCK_BYTES = 5 * 1024 * 1024;
constexpr uint32_t MAX_CONCURRENT_READS = 8;
constexpr char VIRTUAL_ENTRY_ASHMEM_NAME[] = "UdmfVirtualEntry";

std::atomic<uint32_t> g_activeReads{ 0 };

bool IsValidName(const std::string &name)
{
    return !name.empty() && name.size() <= MAX_VIRTUAL_ENTRY_NAME_BYTES && name != "." && name != ".." &&
           name.find_first_of("/\\") == std::string::npos && name.find('\0') == std::string::npos;
}

bool IsValidId(const std::string &id)
{
    return !id.empty() && id.size() <= MAX_VIRTUAL_ENTRY_ID_BYTES && id.find('\0') == std::string::npos;
}

bool ValidateVirtualEntry(const VirtualEntry &entry, uint32_t depth, uint32_t &itemCount)
{
    if (depth > MAX_VIRTUAL_ENTRY_DEPTH || itemCount >= MAX_VIRTUAL_ENTRY_COUNT || !IsValidName(entry.name)) {
        return false;
    }
    ++itemCount;
    if (entry.type == VirtualEntryType::FILE) {
        return IsValidId(entry.id) && entry.size >= -1 && entry.subItems.empty();
    }
    if (entry.type != VirtualEntryType::DIRECTORY || !entry.id.empty() || entry.size != -1) {
        return false;
    }
    for (const auto &child : entry.subItems) {
        if (!ValidateVirtualEntry(child, depth + 1, itemCount)) {
            return false;
        }
    }
    return true;
}

bool IsValidVirtualEntry(const VirtualEntry &entry)
{
    uint32_t itemCount = 0;
    return ValidateVirtualEntry(entry, 0, itemCount);
}

bool NeedsStatCallback(const VirtualEntry &entry)
{
    if (entry.type == VirtualEntryType::FILE) {
        return entry.size < 0;
    }
    for (const auto &child : entry.subItems) {
        if (NeedsStatCallback(child)) {
            return true;
        }
    }
    return false;
}

int32_t ConvertCallbackStatus(int status)
{
    if (status == UDMF_E_OK) {
        return 0;
    }
    return status == UDMF_E_INVALID_PARAM ? -EINVAL : -EIO;
}

bool TryAcquireReadSlot()
{
    uint32_t current = g_activeReads.load(std::memory_order_relaxed);
    while (current < MAX_CONCURRENT_READS) {
        uint32_t expected = current;
        if (g_activeReads.compare_exchange_weak(
            expected, current + 1, std::memory_order_acquire, std::memory_order_relaxed)) {
            return true;
        }
        current = expected;
    }
    return false;
}

class ReadSlotGuard final {
public:
    ReadSlotGuard() = default;
    ~ReadSlotGuard()
    {
        g_activeReads.fetch_sub(1, std::memory_order_release);
    }
};

class VirtualEntryProviderNdk final : public IRemoteStub<IVirtualEntryProvider> {
public:
    explicit VirtualEntryProviderNdk(std::shared_ptr<NdkVirtualEntryInfo> info) : info_(std::move(info))
    {
    }

    int32_t Stat(const std::string &id, VirtualEntry &entry) override
    {
        if (!IsValidId(id) || info_ == nullptr || info_->callbacks == nullptr ||
            info_->callbacks->callbacks_.onStat == nullptr) {
            return -EINVAL;
        }
        OH_UdmfVirtualItem *result = info_->callbacks->callbacks_.onStat(info_->callbacks->context_, id.c_str());
        if (result == nullptr) {
            return -EIO;
        }
        std::unique_ptr<OH_UdmfVirtualItem> item(result);
        if (item->cid != NdkStructId::UDMF_VIRTUAL_ITEM_STRUCT_ID || item->entry_.type != VirtualEntryType::FILE ||
            !IsValidVirtualEntry(item->entry_)) {
            return -EINVAL;
        }
        entry = item->entry_;
        return 0;
    }

    int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) override
    {
        if (!IsValidId(id) || offset < 0 || length < 0 || length > PROVIDER_BLOCK_BYTES || info_ == nullptr ||
            info_->callbacks == nullptr || info_->callbacks->callbacks_.onRead == nullptr) {
            return -EINVAL;
        }
        if (length == 0) {
            data.clear();
            return 0;
        }
        if (!TryAcquireReadSlot()) {
            return -EAGAIN;
        }
        ReadSlotGuard guard;
        std::vector<uint8_t> result(static_cast<size_t>(length));
        uint32_t bytesRead = 0;
        int status = info_->callbacks->callbacks_.onRead(
            info_->callbacks->context_, id.c_str(), offset, static_cast<uint32_t>(length), result.data(), &bytesRead);
        int32_t callbackStatus = ConvertCallbackStatus(status);
        if (callbackStatus != 0) {
            return callbackStatus;
        }
        if (bytesRead > static_cast<uint32_t>(length)) {
            return -EINVAL;
        }
        result.resize(bytesRead);
        data = std::move(result);
        return 0;
    }

    int32_t Cancel(const std::vector<std::string> &ids) override
    {
        if (ids.empty()) {
            return 0;
        }
        if (ids.size() > MAX_VIRTUAL_ENTRY_COUNT || info_ == nullptr || info_->callbacks == nullptr ||
            info_->callbacks->callbacks_.onCancel == nullptr) {
            return -EINVAL;
        }
        std::vector<const char *> idList;
        idList.reserve(ids.size());
        for (const auto &id : ids) {
            if (!IsValidId(id)) {
                return -EINVAL;
            }
            idList.emplace_back(id.c_str());
        }
        int status = info_->callbacks->callbacks_.onCancel(
            info_->callbacks->context_, idList.data(), static_cast<uint32_t>(idList.size()));
        return ConvertCallbackStatus(status);
    }

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override
    {
        if (!UTILS::IsNativeCallingToken() || request.ReadInterfaceToken() != GetDescriptor()) {
            LOG_ERROR(UDMF_CAPI, "Reject virtual entry provider request, code=%{public}u", code);
            return -EACCES;
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::STAT)) {
            return OnStatRequest(request, reply);
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::READ)) {
            return OnReadRequest(request, reply);
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::READ_ASYNC)) {
            return OnReadAsyncRequest(request);
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::CANCEL)) {
            std::vector<std::string> ids;
            int32_t ret = request.ReadStringVector(&ids) ? Cancel(ids) : -EINVAL;
            return reply.WriteInt32(ret) ? 0 : -EIO;
        }
        return IRemoteStub<IVirtualEntryProvider>::OnRemoteRequest(code, request, reply, option);
    }

private:
    int32_t OnStatRequest(MessageParcel &request, MessageParcel &reply)
    {
        std::string id;
        VirtualEntry entry;
        int32_t ret = request.ReadString(id) ? Stat(id, entry) : -EINVAL;
        bool writeFailed = !reply.WriteInt32(ret);
        if (ret == 0) {
            writeFailed = writeFailed || !reply.WriteString(entry.id) || !reply.WriteString(entry.name) ||
                          !reply.WriteInt32(static_cast<int32_t>(entry.type)) || !reply.WriteInt64(entry.modifyTime) ||
                          !reply.WriteInt64(entry.size);
        }
        return writeFailed ? -EIO : 0;
    }

    int32_t OnReadRequest(MessageParcel &request, MessageParcel &reply)
    {
        std::string id;
        int64_t offset = 0;
        int32_t length = 0;
        std::vector<uint8_t> bytes;
        int32_t ret = request.ReadString(id) && request.ReadInt64(offset) && request.ReadInt32(length)
                          ? Read(id, offset, length, bytes)
                          : -EINVAL;
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

    int32_t OnReadAsyncRequest(MessageParcel &request)
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

    const std::shared_ptr<NdkVirtualEntryInfo> info_;
};
} // namespace

NdkVirtualEntryCallbacks::NdkVirtualEntryCallbacks(
    const OH_UdmfVirtualFileCallbacks &callbacks, void *context, OH_UdmfVirtualFile_Finalize finalize)
    : callbacks_(callbacks), context_(context), finalize_(finalize)
{
}

NdkVirtualEntryCallbacks::~NdkVirtualEntryCallbacks()
{
    if (context_ != nullptr && finalize_ != nullptr) {
        finalize_(context_);
    }
}

sptr<IVirtualEntryProvider> CreateNdkVirtualEntryProvider(const std::shared_ptr<NdkVirtualEntryInfo> &info)
{
    if (info == nullptr || info->callbacks == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) VirtualEntryProviderNdk(info);
}

bool AttachNdkVirtualEntry(const std::shared_ptr<File> &file, const std::shared_ptr<NdkVirtualEntryInfo> &info)
{
    auto provider = CreateNdkVirtualEntryProvider(info);
    return provider != nullptr &&
           VirtualEntryAttachmentRegistry::Attach(file, info->entry, provider->AsObject(), provider.GetRefPtr());
}
} // namespace OHOS::UDMF

namespace {
bool IsValidVirtualItem(const OH_UdmfVirtualItem *item)
{
    return item != nullptr && item->cid == NdkStructId::UDMF_VIRTUAL_ITEM_STRUCT_ID;
}

bool IsValidVirtualFileInfo(const OH_UdmfVirtualFileInfo *info)
{
    return info != nullptr && info->cid == NdkStructId::UDMF_VIRTUAL_FILE_INFO_STRUCT_ID && info->info_ != nullptr;
}
} // namespace

OH_UdmfVirtualItem *OH_UdmfVirtualItem_CreateFile(const char *name, const char *id, int64_t modifyTime)
{
    if (name == nullptr || id == nullptr || !OHOS::UDMF::IsValidName(name) || !OHOS::UDMF::IsValidId(id)) {
        return nullptr;
    }
    auto *item = new (std::nothrow) OH_UdmfVirtualItem();
    if (item == nullptr) {
        return nullptr;
    }
    item->entry_.name = name;
    item->entry_.id = id;
    item->entry_.type = OHOS::UDMF::VirtualEntryType::FILE;
    item->entry_.modifyTime = modifyTime;
    return item;
}

OH_UdmfVirtualItem *OH_UdmfVirtualItem_CreateDirectory(const char *name, int64_t modifyTime)
{
    if (name == nullptr || !OHOS::UDMF::IsValidName(name)) {
        return nullptr;
    }
    auto *item = new (std::nothrow) OH_UdmfVirtualItem();
    if (item == nullptr) {
        return nullptr;
    }
    item->entry_.name = name;
    item->entry_.type = OHOS::UDMF::VirtualEntryType::DIRECTORY;
    item->entry_.modifyTime = modifyTime;
    return item;
}

void OH_UdmfVirtualItem_Destroy(OH_UdmfVirtualItem *item)
{
    if (IsValidVirtualItem(item)) {
        delete item;
    }
}

int OH_UdmfVirtualItem_SetFileSize(OH_UdmfVirtualItem *item, int64_t size)
{
    if (!IsValidVirtualItem(item) || size < 0) {
        return UDMF_E_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(item->mutex);
    if (item->entry_.type != OHOS::UDMF::VirtualEntryType::FILE) {
        return UDMF_E_INVALID_PARAM;
    }
    item->entry_.size = size;
    return UDMF_E_OK;
}

int OH_UdmfVirtualItem_ClearFileSize(OH_UdmfVirtualItem *item)
{
    if (!IsValidVirtualItem(item)) {
        return UDMF_E_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(item->mutex);
    if (item->entry_.type != OHOS::UDMF::VirtualEntryType::FILE) {
        return UDMF_E_INVALID_PARAM;
    }
    item->entry_.size = -1;
    return UDMF_E_OK;
}

int OH_UdmfVirtualItem_AddChild(OH_UdmfVirtualItem *directory, const OH_UdmfVirtualItem *child)
{
    if (!IsValidVirtualItem(directory) || !IsValidVirtualItem(child) || directory == child) {
        return UDMF_E_INVALID_PARAM;
    }
    std::scoped_lock lock(directory->mutex, child->mutex);
    if (directory->entry_.type != OHOS::UDMF::VirtualEntryType::DIRECTORY) {
        return UDMF_E_INVALID_PARAM;
    }
    auto candidate = directory->entry_;
    candidate.subItems.emplace_back(child->entry_);
    if (!OHOS::UDMF::IsValidVirtualEntry(candidate)) {
        return UDMF_E_INVALID_PARAM;
    }
    directory->entry_ = std::move(candidate);
    return UDMF_E_OK;
}

OH_UdmfVirtualFileInfo *OH_UdmfVirtualFileInfo_Create(const OH_UdmfVirtualItem *itemInfo,
    const OH_UdmfVirtualFileCallbacks *callbacks, void *context, OH_UdmfVirtualFile_Finalize finalize)
{
    if (!IsValidVirtualItem(itemInfo) || callbacks == nullptr ||
        callbacks->structSize < sizeof(OH_UdmfVirtualFileCallbacks) || callbacks->onRead == nullptr ||
        callbacks->onCancel == nullptr || (context != nullptr && finalize == nullptr)) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(itemInfo->mutex);
    if (!OHOS::UDMF::IsValidVirtualEntry(itemInfo->entry_) ||
        (OHOS::UDMF::NeedsStatCallback(itemInfo->entry_) && callbacks->onStat == nullptr)) {
        return nullptr;
    }
    auto *result = new (std::nothrow) OH_UdmfVirtualFileInfo();
    if (result == nullptr) {
        return nullptr;
    }
    auto callbackHolder = std::make_shared<OHOS::UDMF::NdkVirtualEntryCallbacks>(*callbacks, context, finalize);
    result->info_ = std::make_shared<OHOS::UDMF::NdkVirtualEntryInfo>();
    result->info_->entry = itemInfo->entry_;
    result->info_->callbacks = std::move(callbackHolder);
    return result;
}

void OH_UdmfVirtualFileInfo_Destroy(OH_UdmfVirtualFileInfo *info)
{
    if (info != nullptr && info->cid == NdkStructId::UDMF_VIRTUAL_FILE_INFO_STRUCT_ID) {
        delete info;
    }
}

int OH_UdsFileUri_SetVirtualEntry(OH_UdsFileUri *fileUri, const OH_UdmfVirtualFileInfo *info)
{
    if (IsInvalidUdsObjectPtr(fileUri, NdkStructId::UDS_FILE_URI_STRUCT_ID) || !IsValidVirtualFileInfo(info)) {
        return UDMF_E_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(fileUri->mutex);
    fileUri->virtualEntry_ = info->info_;
    return UDMF_E_OK;
}

int OH_UdsFileUri_ClearVirtualEntry(OH_UdsFileUri *fileUri)
{
    if (IsInvalidUdsObjectPtr(fileUri, NdkStructId::UDS_FILE_URI_STRUCT_ID)) {
        return UDMF_E_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(fileUri->mutex);
    fileUri->virtualEntry_.reset();
    return UDMF_E_OK;
}

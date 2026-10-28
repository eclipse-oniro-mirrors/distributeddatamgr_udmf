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

#include "virtual_entry_provider_proxy.h"

#include <cerrno>
#include <cstddef>

#include "ashmem.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS::UDMF {
namespace {
constexpr size_t PROVIDER_BLOCK_BYTES = 5 * 1024 * 1024;

int32_t Send(const sptr<IRemoteObject> &remote, VirtualEntryProviderCode code, MessageParcel &request,
    MessageParcel &reply, int flags = MessageOption::TF_SYNC)
{
    if (remote == nullptr) {
        return -EINVAL;
    }
    MessageOption option(flags);
    return remote->SendRequest(static_cast<uint32_t>(code), request, reply, option);
}

bool ParseEntry(MessageParcel &reply, VirtualEntry &entry)
{
    int32_t type = 0;
    if (!reply.ReadString(entry.id) || !reply.ReadString(entry.name) || !reply.ReadInt32(type) ||
        !reply.ReadInt64(entry.modifyTime) || !reply.ReadInt64(entry.size)) {
        return false;
    }
    if (type != static_cast<int32_t>(VirtualEntryType::FILE) || entry.size < -1) {
        return false;
    }
    entry.type = static_cast<VirtualEntryType>(type);
    return true;
}
} // namespace

void VirtualEntryProviderProxy::EnsureRegistered()
{
    (void)delegator_;
}

int32_t VirtualEntryProviderProxy::Stat(const std::string &id, VirtualEntry &entry)
{
    MessageParcel request;
    MessageParcel reply;
    if (!request.WriteInterfaceToken(IVirtualEntryProvider::GetDescriptor()) || !request.WriteString(id)) {
        return -EINVAL;
    }
    int32_t ret = Send(Remote(), VirtualEntryProviderCode::STAT, request, reply);
    if (ret != 0) {
        return ret;
    }
    ret = reply.ReadInt32();
    return ret == 0 && !ParseEntry(reply, entry) ? -EIO : ret;
}

int32_t VirtualEntryProviderProxy::Read(const std::string &id, int64_t offset, int32_t length,
    std::vector<uint8_t> &data)
{
    if (offset < 0 || length < 0 || static_cast<size_t>(length) > PROVIDER_BLOCK_BYTES) {
        return -EINVAL;
    }
    MessageParcel request;
    MessageParcel reply;
    if (!request.WriteInterfaceToken(IVirtualEntryProvider::GetDescriptor()) || !request.WriteString(id) ||
        !request.WriteInt64(offset) || !request.WriteInt32(length)) {
        return -EINVAL;
    }
    int32_t ret = Send(Remote(), VirtualEntryProviderCode::READ, request, reply);
    if (ret != 0) {
        return ret;
    }
    ret = reply.ReadInt32();
    uint32_t size = 0;
    if (ret != 0 || !reply.ReadUint32(size) || size > static_cast<uint32_t>(length)) {
        return ret != 0 ? ret : -EIO;
    }
    if (size == 0) {
        data.clear();
        return 0;
    }
    sptr<Ashmem> memory = reply.ReadAshmem();
    if (memory == nullptr || memory->GetAshmemSize() < static_cast<int32_t>(size) ||
        !memory->MapReadOnlyAshmem()) {
        return -EIO;
    }
    const auto *buffer = static_cast<const uint8_t *>(memory->ReadFromAshmem(size, 0));
    if (buffer == nullptr) {
        memory->UnmapAshmem();
        memory->CloseAshmem();
        return -EIO;
    }
    data.assign(buffer, buffer + size);
    memory->UnmapAshmem();
    memory->CloseAshmem();
    return 0;
}

int32_t VirtualEntryProviderProxy::ReadAsync(const std::string &id, int64_t offset, int32_t length,
    const sptr<IRemoteObject> &callback)
{
    if (offset < 0 || length < 0 || static_cast<size_t>(length) > PROVIDER_BLOCK_BYTES || callback == nullptr) {
        return -EINVAL;
    }
    MessageParcel request;
    MessageParcel reply;
    if (!request.WriteInterfaceToken(IVirtualEntryProvider::GetDescriptor()) || !request.WriteString(id) ||
        !request.WriteInt64(offset) || !request.WriteInt32(length) || !request.WriteRemoteObject(callback)) {
        return -EINVAL;
    }
    return Send(Remote(), VirtualEntryProviderCode::READ_ASYNC, request, reply, MessageOption::TF_ASYNC);
}

int32_t VirtualEntryProviderProxy::Cancel(const std::vector<std::string> &ids)
{
    MessageParcel request;
    MessageParcel reply;
    if (!request.WriteInterfaceToken(IVirtualEntryProvider::GetDescriptor()) || !request.WriteStringVector(ids)) {
        return -EINVAL;
    }
    return Send(Remote(), VirtualEntryProviderCode::CANCEL, request, reply, MessageOption::TF_ASYNC);
}
} // namespace OHOS::UDMF

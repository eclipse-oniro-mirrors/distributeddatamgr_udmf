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

#include "virtual_entry_read_callback_proxy.h"

#include <cerrno>

#include "ashmem.h"
#include "message_option.h"
#include "message_parcel.h"
#include "virtual_entry_read_callback_stub.h"

namespace OHOS::UDMF {
namespace {
constexpr size_t PROVIDER_BLOCK_BYTES = 5 * 1024 * 1024;
constexpr char VIRTUAL_ENTRY_ASHMEM_NAME[] = "UdmfVirtualEntryResult";
}

int32_t VirtualEntryReadCallbackProxy::OnResult(int32_t status, const std::vector<uint8_t> &data)
{
    if (data.size() > PROVIDER_BLOCK_BYTES || (status != 0 && !data.empty())) {
        return -EINVAL;
    }
    MessageParcel request;
    MessageParcel reply;
    if (!request.WriteInterfaceToken(IVirtualEntryReadCallback::GetDescriptor()) || !request.WriteInt32(status) ||
        !request.WriteUint32(static_cast<uint32_t>(data.size()))) {
        return -EIO;
    }
    if (!data.empty()) {
        sptr<Ashmem> memory = Ashmem::CreateAshmem(VIRTUAL_ENTRY_ASHMEM_NAME, static_cast<int32_t>(data.size()));
        if (memory == nullptr || !memory->MapReadAndWriteAshmem()) {
            return -ENOMEM;
        }
        bool written = memory->WriteToAshmem(data.data(), data.size(), 0);
        memory->UnmapAshmem();
        if (!written || !request.WriteAshmem(memory)) {
            memory->CloseAshmem();
            return -EIO;
        }
    }
    MessageOption option(MessageOption::TF_ASYNC);
    auto remote = Remote();
    return remote == nullptr
        ? -EPIPE
        : remote->SendRequest(static_cast<uint32_t>(VirtualEntryReadCallbackCode::ON_RESULT), request, reply, option);
}

int32_t VirtualEntryReadCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option)
{
    (void)reply;
    if (request.ReadInterfaceToken() != GetDescriptor()) {
        return -EACCES;
    }
    if (code != static_cast<uint32_t>(VirtualEntryReadCallbackCode::ON_RESULT)) {
        return IRemoteStub<IVirtualEntryReadCallback>::OnRemoteRequest(code, request, reply, option);
    }
    int32_t status = 0;
    uint32_t size = 0;
    if (!request.ReadInt32(status) || !request.ReadUint32(size) || size > PROVIDER_BLOCK_BYTES ||
        (status != 0 && size != 0)) {
        return -EINVAL;
    }
    std::vector<uint8_t> data;
    if (size != 0) {
        sptr<Ashmem> memory = request.ReadAshmem();
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
    }
    return OnResult(status, data);
}
} // namespace OHOS::UDMF

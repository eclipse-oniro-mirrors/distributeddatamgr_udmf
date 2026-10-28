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

#include "ashmem.h"
#include "gtest/gtest.h"
#include "iremote_stub.h"
#include "virtual_entry_read_callback_proxy.h"
#include "virtual_entry_read_callback_stub.h"

using namespace testing::ext;

namespace OHOS::UDMF {
namespace {
class TestReadCallback final : public VirtualEntryReadCallbackStub {
public:
    int32_t OnResult(int32_t status, const std::vector<uint8_t> &data) override
    {
        status_ = status;
        bytes_ = data;
        called_ = true;
        return 0;
    }

    bool called_ = false;
    int32_t status_ = -EIO;
    std::vector<uint8_t> bytes_;
};

class TestVirtualEntryProvider final : public IRemoteStub<IVirtualEntryProvider> {
public:
    int32_t Stat(const std::string &id, VirtualEntry &entry) override
    {
        (void)id;
        (void)entry;
        return -ENOSYS;
    }

    int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) override
    {
        (void)id;
        (void)offset;
        (void)length;
        (void)data;
        return -ENOSYS;
    }

    int32_t Cancel(const std::vector<std::string> &ids) override
    {
        (void)ids;
        return -ENOSYS;
    }

    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override
    {
        (void)option;
        tokenMatched_ = request.ReadInterfaceToken() == GetDescriptor();
        if (!tokenMatched_) {
            return -EACCES;
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::READ)) {
            lastId_ = request.ReadString();
            lastOffset_ = request.ReadInt64();
            lastLength_ = request.ReadInt32();
            if (!reply.WriteInt32(readStatus_)) {
                return -EIO;
            }
            uint32_t size = oversizedReply_ ? static_cast<uint32_t>(lastLength_ + 1) : bytes_.size();
            if (!reply.WriteUint32(size)) {
                return -EIO;
            }
            if (!oversizedReply_ && !bytes_.empty()) {
                sptr<Ashmem> memory = Ashmem::CreateAshmem("VirtualEntryProviderProxyTest", bytes_.size());
                if (memory == nullptr || !memory->MapReadAndWriteAshmem()) {
                    return -ENOMEM;
                }
                bool written = memory->WriteToAshmem(bytes_.data(), bytes_.size(), 0);
                memory->UnmapAshmem();
                if (!written || !reply.WriteAshmem(memory)) {
                    return -EIO;
                }
            }
            return 0;
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::READ_ASYNC)) {
            lastId_ = request.ReadString();
            lastOffset_ = request.ReadInt64();
            lastLength_ = request.ReadInt32();
            sptr<IRemoteObject> callback = request.ReadRemoteObject();
            if (callback == nullptr) {
                return -EINVAL;
            }
            VirtualEntryReadCallbackProxy callbackProxy(callback);
            return callbackProxy.OnResult(readStatus_, readStatus_ == 0 ? bytes_ : std::vector<uint8_t>{});
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::CANCEL)) {
            cancelReceived_ = request.ReadStringVector(&cancelIds_);
            return 0;
        }
        return -EINVAL;
    }

    bool tokenMatched_ = false;
    bool oversizedReply_ = false;
    bool cancelReceived_ = false;
    int32_t readStatus_ = 0;
    int64_t lastOffset_ = 0;
    int32_t lastLength_ = 0;
    std::string lastId_;
    std::vector<uint8_t> bytes_{ 1, 2, 3 };
    std::vector<std::string> cancelIds_;
};
} // namespace

class VirtualEntryProviderProxyTest : public testing::Test {
};

/**
 * @tc.name: Read_ValidReply_ReturnProviderBytes
 * @tc.desc: Verify provider read IPC writes the token first and returns the requested bytes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_ValidReply_ReturnProviderBytes, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    std::vector<uint8_t> data;

    EXPECT_EQ(proxy.Read("file-id", 16, 32, data), 0);
    EXPECT_TRUE(remote->tokenMatched_);
    EXPECT_EQ(remote->lastId_, "file-id");
    EXPECT_EQ(remote->lastOffset_, 16);
    EXPECT_EQ(remote->lastLength_, 32);
    EXPECT_EQ(data, remote->bytes_);
}

/**
 * @tc.name: Read_ReplyExceedsRequestedLength_ReturnIoError
 * @tc.desc: Verify malformed provider replies cannot overrun the requested read length.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_ReplyExceedsRequestedLength_ReturnIoError, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    remote->oversizedReply_ = true;
    VirtualEntryProviderProxy proxy(remote->AsObject());
    std::vector<uint8_t> data;

    EXPECT_EQ(proxy.Read("file-id", 0, 2, data), -EIO);
    EXPECT_TRUE(data.empty());
}

/**
 * @tc.name: Read_ProviderTimeout_PropagateTimeout
 * @tc.desc: Verify a provider timeout is returned unchanged to the FUSE service.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_ProviderTimeout_PropagateTimeout, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    remote->readStatus_ = -ETIMEDOUT;
    VirtualEntryProviderProxy proxy(remote->AsObject());
    std::vector<uint8_t> data;

    EXPECT_EQ(proxy.Read("file-id", 0, 32, data), -ETIMEDOUT);
    EXPECT_TRUE(data.empty());
}

/**
 * @tc.name: ReadAsync_ValidRequest_DeliverCallback
 * @tc.desc: Verify asynchronous provider reads preserve request fields and return bytes through the callback.
 * @tc.type: FUNC
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadAsync_ValidRequest_DeliverCallback, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    sptr<TestReadCallback> callback = new TestReadCallback();
    VirtualEntryProviderProxy proxy(remote->AsObject());

    EXPECT_EQ(proxy.ReadAsync("async-file", 64, 128, callback->AsObject()), 0);
    EXPECT_TRUE(remote->tokenMatched_);
    EXPECT_EQ(remote->lastId_, "async-file");
    EXPECT_EQ(remote->lastOffset_, 64);
    EXPECT_EQ(remote->lastLength_, 128);
    EXPECT_TRUE(callback->called_);
    EXPECT_EQ(callback->status_, 0);
    EXPECT_EQ(callback->bytes_, remote->bytes_);
}

/**
 * @tc.name: ReadCallback_OversizedResult_ReturnInvalidArgument
 * @tc.desc: Verify an oversized asynchronous result is rejected before it enters the callback parcel.
 * @tc.type: FUNC
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_OversizedResult_ReturnInvalidArgument, TestSize.Level0)
{
    constexpr size_t providerBlockBytes = 5 * 1024 * 1024;
    sptr<TestReadCallback> callback = new TestReadCallback();
    VirtualEntryReadCallbackProxy callbackProxy(callback->AsObject());
    std::vector<uint8_t> bytes(providerBlockBytes + 1, 0);

    EXPECT_EQ(callbackProxy.OnResult(0, bytes), -EINVAL);
    EXPECT_FALSE(callback->called_);
}

/**
 * @tc.name: Cancel_ValidIds_SendAsynchronousRequest
 * @tc.desc: Verify session cleanup propagates the affected file identifiers to the provider.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Cancel_ValidIds_SendAsynchronousRequest, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    std::vector<std::string> ids{ "file-a", "file-b" };

    EXPECT_EQ(proxy.Cancel(ids), 0);
    EXPECT_TRUE(remote->tokenMatched_);
    EXPECT_TRUE(remote->cancelReceived_);
    EXPECT_EQ(remote->cancelIds_, ids);
}
} // namespace OHOS::UDMF

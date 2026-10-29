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

#include <algorithm>
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
        flags_ = option.GetFlags();
        tokenMatched_ = request.ReadInterfaceToken() == GetDescriptor();
        if (!tokenMatched_) {
            return -EACCES;
        }
        if (sendStatus_ != 0) {
            return sendStatus_;
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::STAT)) {
            lastId_ = request.ReadString();
            return WriteStatReply(reply);
        }
        if (code == static_cast<uint32_t>(VirtualEntryProviderCode::READ)) {
            lastId_ = request.ReadString();
            lastOffset_ = request.ReadInt64();
            lastLength_ = request.ReadInt32();
            return WriteReadReply(reply);
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
    bool omitSize_ = false;
    bool omitMemory_ = false;
    int32_t memoryBytes_ = -1;
    int32_t sendStatus_ = 0;
    int32_t statStatus_ = 0;
    int32_t statFields_ = 5;
    int32_t statType_ = static_cast<int32_t>(VirtualEntryType::FILE);
    int64_t statSize_ = 3;
    int flags_ = 0;
    int32_t readStatus_ = 0;
    int64_t lastOffset_ = 0;
    int32_t lastLength_ = 0;
    std::string lastId_;
    std::vector<uint8_t> bytes_{ 1, 2, 3 };
    std::vector<std::string> cancelIds_;

private:
    int32_t WriteStatReply(MessageParcel &reply)
    {
        if (!reply.WriteInt32(statStatus_)) {
            return -EIO;
        }
        if (statFields_ > 0) {
            (void)reply.WriteString(lastId_);
        }
        if (statFields_ > 1) {
            (void)reply.WriteString("example.bin");
        }
        if (statFields_ > 2) {
            (void)reply.WriteInt32(statType_);
        }
        if (statFields_ > 3) {
            (void)reply.WriteInt64(123);
        }
        if (statFields_ > 4) {
            (void)reply.WriteInt64(statSize_);
        }
        return 0;
    }

    int32_t WriteReadReply(MessageParcel &reply)
    {
        if (!reply.WriteInt32(readStatus_)) {
            return -EIO;
        }
        if (omitSize_) {
            return 0;
        }
        uint32_t size = oversizedReply_ ? static_cast<uint32_t>(lastLength_ + 1) : bytes_.size();
        if (!reply.WriteUint32(size)) {
            return -EIO;
        }
        if (oversizedReply_ || bytes_.empty() || omitMemory_) {
            return 0;
        }
        int32_t capacity = memoryBytes_ < 0 ? static_cast<int32_t>(bytes_.size()) : memoryBytes_;
        sptr<Ashmem> memory = Ashmem::CreateAshmem("VirtualEntryProviderProxyTest", capacity);
        if (memory == nullptr || !memory->MapReadAndWriteAshmem()) {
            return -ENOMEM;
        }
        bool written = memory->WriteToAshmem(bytes_.data(), std::min(bytes_.size(), static_cast<size_t>(capacity)), 0);
        memory->UnmapAshmem();
        return written && reply.WriteAshmem(memory) ? 0 : -EIO;
    }
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

/**
 * @tc.name: Stat_CompleteMetadata_PreserveFields
 * @tc.desc: Verify stat metadata is decoded without losing identifiers, type, size or modification time.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Stat_CompleteMetadata_PreserveFields, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    VirtualEntry entry;
    ASSERT_EQ(proxy.Stat("stat-file", entry), 0);
    EXPECT_TRUE(remote->tokenMatched_);
    EXPECT_EQ(remote->lastId_, "stat-file");
    EXPECT_EQ(entry.id, "stat-file");
    EXPECT_EQ(entry.name, "example.bin");
    EXPECT_EQ(entry.type, VirtualEntryType::FILE);
    EXPECT_EQ(entry.modifyTime, 123);
    EXPECT_EQ(entry.size, 3);
}

/**
 * @tc.name: Stat_NegativeFileSize_RejectEveryNegativeValue
 * @tc.desc: Verify minus one is rejected together with all other negative file sizes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Stat_NegativeFileSize_RejectEveryNegativeValue, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    VirtualEntry entry;
    remote->statSize_ = -1;
    EXPECT_EQ(proxy.Stat("file", entry), -EIO);
    remote->statSize_ = -2;
    EXPECT_EQ(proxy.Stat("file", entry), -EIO);
}

/**
 * @tc.name: Stat_TruncatedMetadata_RejectEveryMissingField
 * @tc.desc: Verify each mandatory metadata field must be present.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Stat_TruncatedMetadata_RejectEveryMissingField, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    for (int32_t fields = 0; fields < 5; ++fields) {
        SCOPED_TRACE(fields);
        remote->statFields_ = fields;
        VirtualEntry entry;
        EXPECT_EQ(proxy.Stat("file", entry), -EIO);
    }
}

/**
 * @tc.name: Stat_InvalidFileType_RejectDirectoryAndUnknownType
 * @tc.desc: Verify stat cannot replace a virtual file with a directory or an unknown type.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Stat_InvalidFileType_RejectDirectoryAndUnknownType, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    VirtualEntry entry;
    for (auto type : { static_cast<int32_t>(VirtualEntryType::DIRECTORY), 99 }) {
        SCOPED_TRACE(type);
        remote->statType_ = type;
        EXPECT_EQ(proxy.Stat("file", entry), -EIO);
    }
}

/**
 * @tc.name: Stat_ProviderOrTransportFailure_PropagateError
 * @tc.desc: Verify application errors and IPC transport errors remain distinguishable.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Stat_ProviderOrTransportFailure_PropagateError, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    VirtualEntry entry;
    remote->statStatus_ = -ENOENT;
    EXPECT_EQ(proxy.Stat("file", entry), -ENOENT);
    remote->sendStatus_ = -EPIPE;
    EXPECT_EQ(proxy.Stat("file", entry), -EPIPE);
}

/**
 * @tc.name: Provider_NullRemote_RejectWithoutIpc
 * @tc.desc: Verify operations with a missing remote cannot return success.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Provider_NullRemote_RejectWithoutIpc, TestSize.Level0)
{
    VirtualEntryProviderProxy proxy(nullptr);
    VirtualEntry entry;
    std::vector<uint8_t> bytes;
    sptr<TestReadCallback> callback = new TestReadCallback();
    EXPECT_EQ(proxy.Stat("file", entry), -EINVAL);
    EXPECT_EQ(proxy.Read("file", 0, 1, bytes), -EINVAL);
    EXPECT_EQ(proxy.ReadAsync("file", 0, 1, callback->AsObject()), -EINVAL);
    EXPECT_EQ(proxy.Cancel({ "file" }), -EINVAL);
}

/**
 * @tc.name: Read_InvalidRange_RejectBeforeSendingRequest
 * @tc.desc: Verify negative offsets, negative lengths and oversized requests never reach the provider.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_InvalidRange_RejectBeforeSendingRequest, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    std::vector<uint8_t> bytes;
    EXPECT_EQ(proxy.Read("file", -1, 1, bytes), -EINVAL);
    EXPECT_EQ(proxy.Read("file", 0, -1, bytes), -EINVAL);
    EXPECT_EQ(proxy.Read("file", 0, 5 * 1024 * 1024 + 1, bytes), -EINVAL);
    EXPECT_TRUE(remote->lastId_.empty());
    EXPECT_TRUE(bytes.empty());
}

/**
 * @tc.name: Read_EmptyReply_ClearPreviousBuffer
 * @tc.desc: Verify an empty successful reply clears a reused output buffer.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_EmptyReply_ClearPreviousBuffer, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    remote->bytes_.clear();
    std::vector<uint8_t> bytes{ 7, 8 };
    EXPECT_EQ(proxy.Read("file", 0, 0, bytes), 0);
    EXPECT_TRUE(bytes.empty());
    EXPECT_EQ(proxy.Read("file", 0, 5 * 1024 * 1024, bytes), 0);
    EXPECT_TRUE(bytes.empty());
}

/**
 * @tc.name: Read_MissingSize_RejectTruncatedReply
 * @tc.desc: Verify a successful status without a payload length is malformed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_MissingSize_RejectTruncatedReply, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    remote->omitSize_ = true;
    std::vector<uint8_t> bytes;
    EXPECT_EQ(proxy.Read("file", 0, 32, bytes), -EIO);
    EXPECT_TRUE(bytes.empty());
}

/**
 * @tc.name: Read_MissingOrUndersizedMemory_ReturnIoError
 * @tc.desc: Verify declared bytes cannot be read from absent or smaller shared memory.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_MissingOrUndersizedMemory_ReturnIoError, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    std::vector<uint8_t> bytes;
    remote->omitMemory_ = true;
    EXPECT_EQ(proxy.Read("file", 0, 32, bytes), -EIO);
    remote->omitMemory_ = false;
    remote->memoryBytes_ = 2;
    EXPECT_EQ(proxy.Read("file", 0, 32, bytes), -EIO);
    EXPECT_TRUE(bytes.empty());
}

/**
 * @tc.name: Read_TransportFailure_PropagateFailure
 * @tc.desc: Verify a failed IPC does not deliver provider content.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Read_TransportFailure_PropagateFailure, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    remote->sendStatus_ = -EPIPE;
    std::vector<uint8_t> bytes;
    EXPECT_EQ(proxy.Read("file", 0, 32, bytes), -EPIPE);
    EXPECT_TRUE(bytes.empty());
}

/**
 * @tc.name: ReadAsync_InvalidArguments_RejectWithoutCallback
 * @tc.desc: Verify invalid async ranges and missing callbacks are rejected before IPC.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadAsync_InvalidArguments_RejectWithoutCallback, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    sptr<TestReadCallback> callback = new TestReadCallback();
    EXPECT_EQ(proxy.ReadAsync("file", -1, 1, callback->AsObject()), -EINVAL);
    EXPECT_EQ(proxy.ReadAsync("file", 0, -1, callback->AsObject()), -EINVAL);
    EXPECT_EQ(proxy.ReadAsync("file", 0, 5 * 1024 * 1024 + 1, callback->AsObject()), -EINVAL);
    EXPECT_EQ(proxy.ReadAsync("file", 0, 1, nullptr), -EINVAL);
    EXPECT_FALSE(callback->called_);
    EXPECT_TRUE(remote->lastId_.empty());
}

/**
 * @tc.name: ReadAsync_TransportFailure_DoNotInvokeCallback
 * @tc.desc: Verify transport failure does not fabricate an asynchronous completion.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadAsync_TransportFailure_DoNotInvokeCallback, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    remote->sendStatus_ = -EPIPE;
    sptr<TestReadCallback> callback = new TestReadCallback();
    EXPECT_EQ(proxy.ReadAsync("file", 0, 1, callback->AsObject()), -EPIPE);
    EXPECT_FALSE(callback->called_);
}

/**
 * @tc.name: ReadAsync_ProviderFailure_DeliverEmptyErrorResult
 * @tc.desc: Verify provider errors use a one-way request and an empty error callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadAsync_ProviderFailure_DeliverEmptyErrorResult, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    remote->readStatus_ = -ECANCELED;
    sptr<TestReadCallback> callback = new TestReadCallback();
    ASSERT_EQ(proxy.ReadAsync("file", 0, 1, callback->AsObject()), 0);
    EXPECT_EQ(remote->flags_, MessageOption::TF_ASYNC);
    EXPECT_TRUE(callback->called_);
    EXPECT_EQ(callback->status_, -ECANCELED);
    EXPECT_TRUE(callback->bytes_.empty());
}

/**
 * @tc.name: Cancel_EmptyListOrTransportError_PreserveRequestSemantics
 * @tc.desc: Verify empty cancel lists are serialized and transport errors are returned.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, Cancel_EmptyListOrTransportError_PreserveRequestSemantics, TestSize.Level0)
{
    sptr<TestVirtualEntryProvider> remote = new TestVirtualEntryProvider();
    VirtualEntryProviderProxy proxy(remote->AsObject());
    EXPECT_EQ(proxy.Cancel({}), 0);
    EXPECT_TRUE(remote->cancelReceived_);
    EXPECT_TRUE(remote->cancelIds_.empty());
    EXPECT_EQ(remote->flags_, MessageOption::TF_ASYNC);
    remote->sendStatus_ = -EPIPE;
    EXPECT_EQ(proxy.Cancel({ "file" }), -EPIPE);
}

/**
 * @tc.name: ReadCallback_ErrorWithPayload_RejectInvalidCombination
 * @tc.desc: Verify error callbacks cannot carry content bytes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_ErrorWithPayload_RejectInvalidCombination, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    VirtualEntryReadCallbackProxy proxy(callback->AsObject());
    EXPECT_EQ(proxy.OnResult(-EIO, { 1 }), -EINVAL);
    EXPECT_FALSE(callback->called_);
}

/**
 * @tc.name: ReadCallback_EmptyResults_ForwardSuccessAndFailure
 * @tc.desc: Verify empty content is valid for EOF and for an error result.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_EmptyResults_ForwardSuccessAndFailure, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    VirtualEntryReadCallbackProxy proxy(callback->AsObject());
    EXPECT_EQ(proxy.OnResult(0, {}), 0);
    EXPECT_TRUE(callback->called_);
    EXPECT_EQ(callback->status_, 0);
    EXPECT_TRUE(callback->bytes_.empty());
    callback->called_ = false;
    EXPECT_EQ(proxy.OnResult(-ETIMEDOUT, {}), 0);
    EXPECT_TRUE(callback->called_);
    EXPECT_EQ(callback->status_, -ETIMEDOUT);
}

/**
 * @tc.name: ReadCallback_NullRemote_ReturnBrokenPipe
 * @tc.desc: Verify a valid callback payload with no receiver reports a broken pipe.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_NullRemote_ReturnBrokenPipe, TestSize.Level0)
{
    VirtualEntryReadCallbackProxy proxy(nullptr);
    EXPECT_EQ(proxy.OnResult(0, {}), -EPIPE);
}

/**
 * @tc.name: ReadCallback_WrongToken_ReturnAccessDenied
 * @tc.desc: Verify callback dispatch checks the interface descriptor before reading data.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_WrongToken_ReturnAccessDenied, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    MessageParcel request;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(request.WriteInterfaceToken(u"invalid.callback"));
    EXPECT_EQ(callback->OnRemoteRequest(0, request, reply, option), -EACCES);
    EXPECT_FALSE(callback->called_);
}

/**
 * @tc.name: ReadCallback_MalformedHeaders_RejectWithoutDelivery
 * @tc.desc: Verify truncated headers, oversized counts and error payload declarations are rejected.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_MalformedHeaders_RejectWithoutDelivery, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    for (int fields = 0; fields < 4; ++fields) {
        SCOPED_TRACE(fields);
        MessageParcel request;
        MessageParcel reply;
        MessageOption option;
        ASSERT_TRUE(request.WriteInterfaceToken(IVirtualEntryReadCallback::GetDescriptor()));
        if (fields > 0) {
            ASSERT_TRUE(request.WriteInt32(fields == 3 ? -EIO : 0));
        }
        if (fields > 1) {
            ASSERT_TRUE(request.WriteUint32(fields == 3 ? 1 : 5 * 1024 * 1024 + 1));
        }
        EXPECT_EQ(callback->OnRemoteRequest(static_cast<uint32_t>(VirtualEntryReadCallbackCode::ON_RESULT),
            request, reply, option), -EINVAL);
        EXPECT_FALSE(callback->called_);
    }
}

/**
 * @tc.name: ReadCallback_MissingMemory_RejectDeclaredPayload
 * @tc.desc: Verify nonempty data requires a shared-memory object.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_MissingMemory_RejectDeclaredPayload, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    MessageParcel request;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(request.WriteInterfaceToken(IVirtualEntryReadCallback::GetDescriptor()));
    ASSERT_TRUE(request.WriteInt32(0));
    ASSERT_TRUE(request.WriteUint32(1));
    EXPECT_EQ(callback->OnRemoteRequest(static_cast<uint32_t>(VirtualEntryReadCallbackCode::ON_RESULT),
        request, reply, option), -EIO);
    EXPECT_FALSE(callback->called_);
}

/**
 * @tc.name: ReadCallback_UndersizedMemory_RejectWithoutDelivery
 * @tc.desc: Verify shared-memory capacity is checked against the declared payload.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_UndersizedMemory_RejectWithoutDelivery, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    MessageParcel request;
    MessageParcel reply;
    MessageOption option;
    sptr<Ashmem> memory = Ashmem::CreateAshmem("CallbackShortMemory", 1);
    ASSERT_NE(memory, nullptr);
    ASSERT_TRUE(request.WriteInterfaceToken(IVirtualEntryReadCallback::GetDescriptor()));
    ASSERT_TRUE(request.WriteInt32(0));
    ASSERT_TRUE(request.WriteUint32(2));
    ASSERT_TRUE(request.WriteAshmem(memory));
    EXPECT_EQ(callback->OnRemoteRequest(static_cast<uint32_t>(VirtualEntryReadCallbackCode::ON_RESULT),
        request, reply, option), -EIO);
    EXPECT_FALSE(callback->called_);
}

/**
 * @tc.name: ReadCallback_UnknownCode_DoNotDeliverResult
 * @tc.desc: Verify unsupported transactions do not invoke the callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryProviderProxyTest, ReadCallback_UnknownCode_DoNotDeliverResult, TestSize.Level0)
{
    sptr<TestReadCallback> callback = new TestReadCallback();
    MessageParcel request;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(request.WriteInterfaceToken(IVirtualEntryReadCallback::GetDescriptor()));
    EXPECT_NE(callback->OnRemoteRequest(0xFFFF, request, reply, option), 0);
    EXPECT_FALSE(callback->called_);
}
} // namespace OHOS::UDMF

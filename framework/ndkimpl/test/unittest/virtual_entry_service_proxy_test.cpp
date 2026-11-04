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

#include "udmf_service_proxy.h"

#include <string>

#include "gtest/gtest.h"
#include "iremote_stub.h"
#include "virtual_entry.h"

using namespace testing::ext;

namespace OHOS::UDMF {
namespace {
constexpr int64_t TEST_MODIFY_TIME = 123;
constexpr int64_t TEST_FILE_SIZE = 7;

class TestUdmfService final : public IRemoteStub<IUdmfService> {
public:
    int32_t SetData(CustomOption &, UnifiedData &, Summary &, std::string &) override { return 0; }
    int32_t GetData(const QueryOption &, UnifiedData &) override { return 0; }
    int32_t GetBatchData(const QueryOption &, std::vector<UnifiedData> &) override { return 0; }
    int32_t UpdateData(const QueryOption &, UnifiedData &) override { return 0; }
    int32_t DeleteData(const QueryOption &, std::vector<UnifiedData> &) override { return 0; }
    int32_t GetSummary(const QueryOption &, Summary &) override { return 0; }
    int32_t AddPrivilege(const QueryOption &, Privilege &) override { return 0; }
    int32_t Sync(const QueryOption &, const std::vector<std::string> &) override { return 0; }
    int32_t IsRemoteData(const QueryOption &, bool &) override { return 0; }
    int32_t SetAppShareOption(const std::string &, int32_t) override { return 0; }
    int32_t GetAppShareOption(const std::string &, int32_t &) override { return 0; }
    int32_t RemoveAppShareOption(const std::string &) override { return 0; }
    int32_t ObtainAsynProcess(AsyncProcessInfo &) override { return 0; }
    int32_t ClearAsynProcessByKey(const std::string &) override { return 0; }
    int32_t SetDelayInfo(const DataLoadInfo &, sptr<IRemoteObject>, std::string &) override { return 0; }
    int32_t PushDelayData(const std::string &, UnifiedData &, Summary &) override { return 0; }
    int32_t GetDataIfAvailable(const std::string &, const DataLoadInfo &, sptr<IRemoteObject>,
        std::shared_ptr<UnifiedData>) override { return 0; }
    int32_t RegisterVirtualEntry(const std::string &, uint32_t, const VirtualEntry &,
        sptr<IRemoteObject>) override { return 0; }

    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override
    {
        if (request.ReadInterfaceToken() != GetDescriptor()) {
            return -EACCES;
        }
        if (code != static_cast<uint32_t>(UdmfServiceInterfaceCode::REGISTER_VIRTUAL_ENTRY)) {
            return IPCObjectStub::OnRemoteRequest(code, request, reply, option);
        }
        receivedKey_ = request.ReadString();
        receivedRecordIndex_ = request.ReadUint32();
        ReadVirtualEntryFromParcel(request);
        receivedProvider_ = request.ReadRemoteObject();
        reply.WriteInt32(replyStatus_);
        return 0;
    }

    int32_t replyStatus_ = E_OK;
    std::string receivedKey_;
    uint32_t receivedRecordIndex_ = 0;
    sptr<IRemoteObject> receivedProvider_;

private:
    void ReadVirtualEntryFromParcel(MessageParcel &request)
    {
        (void)request.ReadString();
        (void)request.ReadString();
        (void)request.ReadInt32();
        (void)request.ReadInt64();
        (void)request.ReadInt64();
        uint32_t childCount = request.ReadUint32();
        for (uint32_t i = 0; i < childCount; ++i) {
            ReadVirtualEntryFromParcel(request);
        }
    }
};

VirtualEntry MakeValidFileEntry()
{
    VirtualEntry entry;
    entry.id = "file-id";
    entry.name = "example.bin";
    entry.type = VirtualEntryType::FILE;
    entry.modifyTime = TEST_MODIFY_TIME;
    entry.size = TEST_FILE_SIZE;
    return entry;
}
} // namespace

class VirtualEntryServiceProxyTest : public testing::Test {
};

/**
 * @tc.name: RegisterVirtualEntry_EmptyKey_ReturnsInvalidParameters
 * @tc.desc: Verify an empty key is rejected before IPC.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_EmptyKey_ReturnsInvalidParameters, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    UdmfServiceProxy proxy(remote->AsObject());
    VirtualEntry entry = MakeValidFileEntry();
    EXPECT_EQ(proxy.RegisterVirtualEntry("", 0, entry, remote->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_NullProvider_ReturnsInvalidParameters
 * @tc.desc: Verify a null provider is rejected before IPC.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_NullProvider_ReturnsInvalidParameters, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    UdmfServiceProxy proxy(remote->AsObject());
    VirtualEntry entry = MakeValidFileEntry();
    EXPECT_EQ(proxy.RegisterVirtualEntry("key", 0, entry, nullptr), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_InvalidEntry_ReturnsInvalidParameters
 * @tc.desc: Verify an entry with unset file sizes is rejected before IPC.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_InvalidEntry_ReturnsInvalidParameters, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    UdmfServiceProxy proxy(remote->AsObject());
    VirtualEntry entry = MakeValidFileEntry();
    entry.size = -1;
    EXPECT_EQ(proxy.RegisterVirtualEntry("key", 0, entry, remote->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_NullRemote_ReturnsIpcError
 * @tc.desc: Verify a missing service remote reports an IPC error after writing the parcel.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_NullRemote_ReturnsIpcError, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    UdmfServiceProxy proxy(nullptr);
    VirtualEntry entry = MakeValidFileEntry();
    EXPECT_EQ(proxy.RegisterVirtualEntry("key", 0, entry, remote->AsObject()), E_IPC);
}

/**
 * @tc.name: RegisterVirtualEntry_ValidRequest_PreservesKeyAndIndex
 * @tc.desc: Verify a valid registration preserves the key and record index in the IPC request.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_ValidRequest_PreservesKeyAndIndex, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    remote->replyStatus_ = E_OK;
    UdmfServiceProxy proxy(remote->AsObject());
    VirtualEntry entry = MakeValidFileEntry();
    EXPECT_EQ(proxy.RegisterVirtualEntry("drag-key", 3, entry, remote->AsObject()), E_OK);
    EXPECT_EQ(remote->receivedKey_, "drag-key");
    EXPECT_EQ(remote->receivedRecordIndex_, 3u);
    EXPECT_NE(remote->receivedProvider_, nullptr);
}

/**
 * @tc.name: RegisterVirtualEntry_ServiceFailure_PropagatesStatus
 * @tc.desc: Verify the service reply status is returned to the caller.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_ServiceFailure_PropagatesStatus, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    remote->replyStatus_ = E_INVALID_PARAMETERS;
    UdmfServiceProxy proxy(remote->AsObject());
    VirtualEntry entry = MakeValidFileEntry();
    EXPECT_EQ(proxy.RegisterVirtualEntry("key", 0, entry, remote->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_NestedDirectory_SerializesTree
 * @tc.desc: Verify a directory entry with children is fully serialized without IPC error.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryServiceProxyTest, RegisterVirtualEntry_NestedDirectory_SerializesTree, TestSize.Level0)
{
    sptr<TestUdmfService> remote = new TestUdmfService();
    UdmfServiceProxy proxy(remote->AsObject());
    VirtualEntry entry;
    entry.name = "root";
    entry.type = VirtualEntryType::DIRECTORY;
    entry.modifyTime = TEST_MODIFY_TIME;
    VirtualEntry child = MakeValidFileEntry();
    entry.subItems.push_back(child);
    VirtualEntry nestedDir;
    nestedDir.name = "nested";
    nestedDir.type = VirtualEntryType::DIRECTORY;
    nestedDir.modifyTime = TEST_MODIFY_TIME;
    VirtualEntry nestedChild = MakeValidFileEntry();
    nestedChild.id = "nested-file";
    nestedChild.name = "nested.bin";
    nestedDir.subItems.push_back(nestedChild);
    entry.subItems.push_back(nestedDir);
    EXPECT_EQ(proxy.RegisterVirtualEntry("key", 0, entry, remote->AsObject()), E_OK);
    EXPECT_EQ(remote->receivedKey_, "key");
}
} // namespace OHOS::UDMF

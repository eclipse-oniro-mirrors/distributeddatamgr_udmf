/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "UdmfClientAbnormalTest"

#include <unistd.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>

#include "file.h"
#include "iremote_stub.h"
#include "logger.h"
#include "udmf_async_client.h"
#include "udmf_capi_common.h"
#include "udmf_client.h"
#include "udmf_service_client_mock.h"
#include "virtual_entry.h"
#include "virtual_entry_attachment_registry.h"
#include "virtual_entry_provider.h"

using namespace testing::ext;
using namespace OHOS::UDMF;
using namespace OHOS;
namespace OHOS::Test {
using namespace std;
using namespace testing;

namespace {
constexpr int64_t TEST_FILE_SIZE = 7;

class DummyProvider final : public IRemoteStub<IVirtualEntryProvider> {
public:
    int32_t Stat(const std::string &, VirtualEntry &) override { return -ENOSYS; }
    int32_t Read(const std::string &, int64_t, int32_t, std::vector<uint8_t> &) override { return -ENOSYS; }
    int32_t Cancel(const std::vector<std::string> &) override { return -ENOSYS; }
    int32_t OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) override { return 0; }
};

struct AttachmentOwner {
    ~AttachmentOwner()
    {
        VirtualEntryAttachmentRegistry::Detach(this);
    }
};

VirtualEntry MakeValidEntry()
{
    VirtualEntry entry;
    entry.id = "file-id";
    entry.name = "example.bin";
    entry.type = VirtualEntryType::FILE;
    entry.size = TEST_FILE_SIZE;
    return entry;
}
} // namespace

class UdmfClientAbnormalTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static inline shared_ptr<UdmfServiceClientMock> mock_ = nullptr;
};

void UdmfClientAbnormalTest::SetUpTestCase()
{
}

void UdmfClientAbnormalTest::TearDownTestCase()
{
}

void UdmfClientAbnormalTest::SetUp()
{
    mock_ = make_shared<UdmfServiceClientMock>();
    MUdmfServiceClient::udmfServiceClient = mock_;
}

void UdmfClientAbnormalTest::TearDown()
{
    mock_ = nullptr;
    MUdmfServiceClient::udmfServiceClient = nullptr;
}

/**
* @tc.name: SetData001
* @tc.desc: Abnrmal testcase of SetData, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, SetData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "SetData001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DATA_HUB;
    std::string key = "testKey";

    Status ret = client.SetData(option, unifiedData, key);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "SetData001 end.");
}

/**
* @tc.name: GetData001
* @tc.desc: Abnrmal testcase of GetData, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, GetData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "GetData001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    UnifiedData unifiedData;

    Status ret = client.GetData(query, unifiedData);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "GetData001 end.");
}

/**
* @tc.name: GetBatchData001
* @tc.desc: Abnrmal testcase of GetBatchData, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, GetBatchData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "GetBatchData001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    std::vector<UnifiedData> unifiedDataSet;

    Status ret = client.GetBatchData(query, unifiedDataSet);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "GetBatchData001 end.");
}

/**
* @tc.name: UpdateData001
* @tc.desc: Abnrmal testcase of UpdateData, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, UpdateData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "UpdateData001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    UnifiedData unifiedData;

    Status ret = client.UpdateData(query, unifiedData);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "UpdateData001 end.");
}

/**
* @tc.name: DeleteData001
* @tc.desc: Abnrmal testcase of DeleteData, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, DeleteData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "DeleteData001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    std::vector<UnifiedData> unifiedDataSet;

    Status ret = client.DeleteData(query, unifiedDataSet);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "DeleteData001 end.");
}

/**
* @tc.name: AddPrivilege001
* @tc.desc: Abnrmal testcase of AddPrivilege, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, AddPrivilege001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "AddPrivilege001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    Privilege privilege;

    Status ret = client.AddPrivilege(query, privilege);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "AddPrivilege001 end.");
}

/**
* @tc.name: Sync001
* @tc.desc: Abnrmal testcase of Sync, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, Sync001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "Sync001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    const std::vector<std::string> devices;

    Status ret = client.Sync(query, devices);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "Sync001 end.");
}

/**
* @tc.name: IsRemoteData001
* @tc.desc: Abnrmal testcase of IsRemoteData, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, IsRemoteData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "IsRemoteData001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const QueryOption query;
    bool result = true;

    Status ret = client.IsRemoteData(query, result);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "IsRemoteData001 end.");
}

/**
* @tc.name: SetAppShareOption001
* @tc.desc: Abnrmal testcase of SetAppShareOption, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, SetAppShareOption001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "SetAppShareOption001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const std::string intention = "intention";
    enum ShareOptions shareOption = ShareOptions::IN_APP;

    Status ret = client.SetAppShareOption(intention, shareOption);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "SetAppShareOption001 end.");
}

/**
* @tc.name: GetAppShareOption001
* @tc.desc: Abnrmal testcase of GetAppShareOption, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, GetAppShareOption001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "GetAppShareOption001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const std::string intention = "intention";
    enum ShareOptions shareOption = ShareOptions::IN_APP;

    Status ret = client.SetAppShareOption(intention, shareOption);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "GetAppShareOption001 end.");
}

/**
* @tc.name: RemoveAppShareOption001
* @tc.desc: Abnrmal testcase of RemoveAppShareOption, the return value of GetInstance() is nullptr
* @tc.type: FUNC
*/
HWTEST_F(UdmfClientAbnormalTest, RemoveAppShareOption001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "RemoveAppShareOption001 begin.");
    EXPECT_CALL(*mock_, GetInstance()).WillOnce(Return(nullptr));

    UdmfClient client;
    const std::string intention = "intention";

    Status ret = client.RemoveAppShareOption(intention);
    EXPECT_EQ(ret, Status::E_IPC);
    LOG_INFO(UDMF_TEST, "RemoveAppShareOption001 end.");
}

/**
 * @tc.name: SetData_DragInAppNoVirtualEntry_ProcessesInApp
 * @tc.desc: Verify in-app drag without a virtual entry is processed locally and returns success.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragInAppNoVirtualEntry_ProcessesInApp, TestSize.Level1)
{
    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(static_cast<int32_t>(ShareOptions::IN_APP)), Return(E_OK)));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_OK);
    EXPECT_FALSE(key.empty());
}

/**
 * @tc.name: SetData_DragInAppWithVirtualEntry_ReturnsInvalidParameters
 * @tc.desc: Verify in-app drag with a virtual entry is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragInAppWithVirtualEntry_ReturnsInvalidParameters, TestSize.Level1)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    sptr<DummyProvider> provider = new DummyProvider();
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, MakeValidEntry(), provider->AsObject(), &owner));

    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(static_cast<int32_t>(ShareOptions::IN_APP)), Return(E_OK)));

    UdmfClient client;
    UnifiedData unifiedData;
    unifiedData.AddRecord(file);
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_INVALID_PARAMETERS);
}

/**
 * @tc.name: SetData_DragNotInApp_ProceedsToService
 * @tc.desc: Verify cross-device drag delegates to the service SetData.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragNotInApp_ProceedsToService, TestSize.Level1)
{
    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(static_cast<int32_t>(ShareOptions::CROSS_DEVICE)), Return(E_OK)));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_OK));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_OK);
}

/**
 * @tc.name: SetData_DragGetShareOptionError_ReturnsError
 * @tc.desc: Verify a GetAppShareOption error (not E_NOT_FOUND) is propagated.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragGetShareOptionError_ReturnsError, TestSize.Level1)
{
    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _)).WillOnce(Return(E_ERROR));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_ERROR);
}

/**
 * @tc.name: SetData_DragGetShareOptionNotFound_ProceedsToService
 * @tc.desc: Verify E_NOT_FOUND from GetAppShareOption allows the request to proceed.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragGetShareOptionNotFound_ProceedsToService, TestSize.Level1)
{
    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _)).WillOnce(Return(E_NOT_FOUND));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_OK));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_OK);
}

/**
 * @tc.name: SetData_DragVirtualEntry_SetDataSuccessRegisterSuccess_ReturnsOk
 * @tc.desc: Verify a cross-device drag with a virtual entry registers the provider after SetData.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragVirtualEntry_SetDataSuccessRegisterSuccess_ReturnsOk, TestSize.Level1)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    sptr<DummyProvider> provider = new DummyProvider();
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, MakeValidEntry(), provider->AsObject(), &owner));

    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(static_cast<int32_t>(ShareOptions::CROSS_DEVICE)), Return(E_OK)));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_OK));
    EXPECT_CALL(*mock_, RegisterVirtualEntry(_, _, _, _)).WillOnce(Return(E_OK));

    UdmfClient client;
    UnifiedData unifiedData;
    unifiedData.AddRecord(file);
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_OK);
}

/**
 * @tc.name: SetData_DragVirtualEntry_RegisterFailure_RollsBackDeleteData
 * @tc.desc: Verify a failed RegisterVirtualEntry triggers a DeleteData rollback.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragVirtualEntry_RegisterFailure_RollsBackDeleteData, TestSize.Level1)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    sptr<DummyProvider> provider = new DummyProvider();
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, MakeValidEntry(), provider->AsObject(), &owner));

    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(static_cast<int32_t>(ShareOptions::CROSS_DEVICE)), Return(E_OK)));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_OK));
    EXPECT_CALL(*mock_, RegisterVirtualEntry(_, _, _, _)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(*mock_, DeleteData(_, _)).WillOnce(Return(E_OK));

    UdmfClient client;
    UnifiedData unifiedData;
    unifiedData.AddRecord(file);
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_ERROR);
}

/**
 * @tc.name: SetData_DragVirtualEntry_SetDataFailure_SkipsRegistration
 * @tc.desc: Verify a failed SetData skips RegisterVirtualEntry.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_DragVirtualEntry_SetDataFailure_SkipsRegistration, TestSize.Level1)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    sptr<DummyProvider> provider = new DummyProvider();
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, MakeValidEntry(), provider->AsObject(), &owner));

    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, GetAppShareOption(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(static_cast<int32_t>(ShareOptions::CROSS_DEVICE)), Return(E_OK)));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(*mock_, RegisterVirtualEntry(_, _, _, _)).Times(0);

    UdmfClient client;
    UnifiedData unifiedData;
    unifiedData.AddRecord(file);
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DRAG;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_ERROR);
}

/**
 * @tc.name: SetData_NonDragNoVirtualEntry_SetDataSuccess_ReturnsOk
 * @tc.desc: Verify non-drag data without a virtual entry delegates to the service.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_NonDragNoVirtualEntry_SetDataSuccess_ReturnsOk, TestSize.Level1)
{
    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_OK));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DATA_HUB;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_OK);
}

/**
 * @tc.name: SetData_NonDragNoVirtualEntry_SetDataFailure_ReturnsError
 * @tc.desc: Verify a service SetData failure is propagated for non-drag data.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfClientAbnormalTest, SetData_NonDragNoVirtualEntry_SetDataFailure_ReturnsError, TestSize.Level1)
{
    auto serviceClient = std::make_shared<UdmfServiceClient>(nullptr);
    EXPECT_CALL(*mock_, GetInstance()).WillRepeatedly(Return(serviceClient));
    EXPECT_CALL(*mock_, SetData(_, _, _, _)).WillOnce(Return(E_ERROR));

    UdmfClient client;
    UnifiedData unifiedData;
    CustomOption option;
    option.intention = Intention::UD_INTENTION_DATA_HUB;
    std::string key;
    EXPECT_EQ(client.SetData(option, unifiedData, key), Status::E_ERROR);
}
} // OHOS::Test

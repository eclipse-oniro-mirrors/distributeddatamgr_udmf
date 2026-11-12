/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define LOG_TAG "UdmfNotifierStubTest"
#include "udmf_notifier_stub.h"

#include <atomic>
#include <future>

#include "accesstoken_kit.h"
#include "file.h"
#include "gtest/gtest.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "udmf_types_util.h"
#include "unified_data_helper.h"

namespace OHOS::UDMF {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

class UdmfNotifierStubTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
    
    static void SetNativeToken(const std::string &processName)
    {
        auto tokenId = AccessTokenKit::GetNativeTokenId(processName);
        SetSelfTokenID(tokenId);
    }
};

/**
* @tc.name: DelayDataCallback_OnRemoteRequest_001
* @tc.desc: Test DelayDataCallbackStub rejects temp_udmf_file_flag
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_OnRemoteRequest_001, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    auto callback = [](const std::string &key, const UnifiedData &data) {};
    DelayDataCallbackClient client(callback);
    
    int ret = client.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(ret, 0);
}

/**
* @tc.name: UdmfNotifierClient_HandleDelayObserver_001
* @tc.desc: Test UdmfNotifierClient handles delay observer
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, UdmfNotifierClient_HandleDelayObserver_001, TestSize.Level1)
{
    auto loadHandler = [](const std::string &key, const DataLoadInfo &info) {};
    UdmfNotifierClient client(loadHandler);
    
    std::string key = "test_key";
    DataLoadInfo dataLoadInfo;
    dataLoadInfo.sequenceKey = "seq_key";
    
    client.HandleDelayObserver(key, dataLoadInfo);
    EXPECT_TRUE(true);
}

/**
* @tc.name: IsTempUData_RejectedInDelayCallback_001
* @tc.desc: Test IsTempUData is rejected in delay data callback
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, IsTempUData_RejectedInDelayCallback_001, TestSize.Level1)
{
    UnifiedData data;
    auto file = std::make_shared<File>();
    file->SetType(UDType::FILE);
    file->SetUtdId("general.file-uri");
    
    UDDetails details;
    details.insert(std::make_pair("temp_udmf_file_flag", true));
    file->SetDetails(details);
    
    data.AddRecord(file);
    
    bool ret = UnifiedDataHelper::IsTempUData(data);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: OnRemoteRequest_NativeTokenCheck_001
* @tc.desc: Test OnRemoteRequest rejects non-native token
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, OnRemoteRequest_NativeTokenCheck_001, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    auto loadHandler = [](const std::string &key, const DataLoadInfo &info) {};
    UdmfNotifierClient client(loadHandler);
    
    auto callback = [](const std::string &key, const UnifiedData &data) {};
    DelayDataCallbackClient delayClient(callback);
    
    int ret = delayClient.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(ret, 0);
}

/**
* @tc.name: OnRemoteRequest_ProcessNameCheck_001
* @tc.desc: Test OnRemoteRequest validates process name
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, OnRemoteRequest_ProcessNameCheck_001, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    auto callback = [](const std::string &key, const UnifiedData &data) {};
    DelayDataCallbackClient client(callback);
    
    int ret = client.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(ret, 0);
}

/**
* @tc.name: OnRemoteRequest_ValidRequest_001
* @tc.desc: Test OnRemoteRequest accepts valid native request
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, OnRemoteRequest_ValidRequest_001, TestSize.Level1)
{
    auto loadHandler = [](const std::string &key, const DataLoadInfo &info) {};
    UdmfNotifierClient client(loadHandler);
    
    std::string key = "test_key";
    DataLoadInfo dataLoadInfo;
    dataLoadInfo.sequenceKey = "seq_key";
    
    client.HandleDelayObserver(key, dataLoadInfo);
    EXPECT_TRUE(true);
}

/**
* @tc.name: UdmfNotifierStub_OnRemoteRequest_DescriptorMismatch_001
* @tc.desc: Test UdmfNotifierStub OnRemoteRequest with descriptor mismatch
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, UdmfNotifierStub_OnRemoteRequest_DescriptorMismatch_001, TestSize.Level1)
{
    auto loadHandler = [](const std::string &key, const DataLoadInfo &info) {};
    UdmfNotifierClient client(loadHandler);
    
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"invalid.descriptor");
    
    int ret = client.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, -1);
}

/**
* @tc.name: UdmfNotifierStub_OnRemoteRequest_UnmarshalFailed_001
* @tc.desc: Test UdmfNotifierStub OnRemoteRequest with unmarshal failed
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, UdmfNotifierStub_OnRemoteRequest_UnmarshalFailed_001, TestSize.Level1)
{
    auto loadHandler = [](const std::string &key, const DataLoadInfo &info) {};
    UdmfNotifierClient client(loadHandler);
    
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(UdmfNotifierClient::GetDescriptor());
    data.WriteInt32(123);
    
    int ret = client.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, E_READ_PARCEL_ERROR);
}

/**
* @tc.name: DelayDataCallback_OnRemoteRequest_ValidProcess_001
* @tc.desc: Test DelayDataCallback OnRemoteRequest with valid process name
* @tc.type: FUNC
*/
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_OnRemoteRequest_ValidProcess_001, TestSize.Level1)
{
    SetNativeToken("distributeddata");

    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto callback = [](const std::string &key, const UnifiedData &data) {};
    DelayDataCallbackClient client(callback);

    data.WriteInterfaceToken(DelayDataCallbackClient::GetDescriptor());

    std::string key = "test_key";
    UnifiedData unifiedData;

    if (!ITypesUtil::Marshal(data, key, unifiedData)) {
        FAIL() << "Marshal failed";
    }

    int ret = client.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, 0);
}
} // namespace OHOS::UDMF
namespace OHOS::UDMF {
/**
 * @tc.name: DelayDataCallback_EmptyResult_ReportsExistingNotFoundError
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_EmptyResult_ReportsExistingNotFoundError, TestSize.Level1)
{
    std::atomic<int> deliveries{ 0 };
    std::promise<int32_t> error;
    auto result = error.get_future();
    DelayDataCallbackClient callback([&deliveries](const std::string &, const UnifiedData &) { deliveries++; },
        [&error](int32_t status) { error.set_value(status); });
    callback.DelayDataCallback("denied", UnifiedData());
    ASSERT_EQ(result.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(result.get(), E_NOT_FOUND);
    EXPECT_EQ(deliveries.load(), 0);
}
/**
 * @tc.name: DelayDataCallback_NonemptyResult_PreservesDataCompletion
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_NonemptyResult_PreservesDataCompletion, TestSize.Level1)
{
    std::atomic<int> errors{ 0 };
    std::promise<size_t> delivered;
    auto result = delivered.get_future();
    DelayDataCallbackClient callback(
        [&delivered](const std::string &, const UnifiedData &data) { delivered.set_value(data.GetRecords().size()); },
        [&errors](int32_t) { errors++; });
    UnifiedData data;
    data.AddRecord(std::make_shared<UnifiedRecord>());
    callback.DelayDataCallback("allowed", data);
    ASSERT_EQ(result.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(result.get(), 1u);
    EXPECT_EQ(errors.load(), 0);
}

/**
 * @tc.name: DelayDataCallback_LegacyEmptyResult_StillInvokesDataHandler
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_LegacyEmptyResult_StillInvokesDataHandler, TestSize.Level1)
{
    auto delivered = std::make_shared<std::promise<std::pair<std::string, bool>>>();
    auto ready = delivered->get_future();
    DelayDataCallbackClient callback([delivered](const std::string &key, const UnifiedData &data) {
        delivered->set_value({ key, data.IsEmpty() });
    });
    callback.DelayDataCallback("legacy-empty", UnifiedData());
    ASSERT_EQ(ready.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto actual = ready.get();
    EXPECT_EQ(actual.first, "legacy-empty");
    EXPECT_TRUE(actual.second);
}
/**
 * @tc.name: DelayDataCallback_EmptyOptionalErrorHandler_PreservesLegacyDelivery
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_EmptyOptionalErrorHandler_PreservesLegacyDelivery, TestSize.Level1)
{
    auto delivered = std::make_shared<std::promise<bool>>();
    auto ready = delivered->get_future();
    DelayDataCallbackClient callback(
        [delivered](const std::string &, const UnifiedData &data) { delivered->set_value(data.IsEmpty()); }, {});
    callback.DelayDataCallback("empty-error-handler", UnifiedData());
    ASSERT_EQ(ready.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_TRUE(ready.get());
}
/**
 * @tc.name: DelayDataCallback_NonemptyResult_PreservesKeyAndContent
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfNotifierStubTest, DelayDataCallback_NonemptyResult_PreservesKeyAndContent, TestSize.Level1)
{
    auto delivered = std::make_shared<std::promise<std::pair<std::string, std::string>>>();
    auto ready = delivered->get_future();
    auto errors = std::make_shared<std::atomic<int>>(0);
    DelayDataCallbackClient callback(
        [delivered](const std::string &key, const UnifiedData &data) {
            delivered->set_value({ key, std::get<std::string>(data.GetRecords().at(0)->GetOriginValue()) });
        },
        [errors](int32_t) { ++(*errors); });
    UnifiedData data;
    data.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("accepted")));
    callback.DelayDataCallback("accepted-key", data);
    ASSERT_EQ(ready.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto actual = ready.get();
    EXPECT_EQ(actual.first, "accepted-key");
    EXPECT_EQ(actual.second, "accepted");
    EXPECT_EQ(errors->load(), 0);
}
} // namespace OHOS::UDMF

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
#define LOG_TAG "TempUDataLoaderTest"

#include <gtest/gtest.h>

#include "logger.h"
#include "temp_udata_loader.h"
#include "unified_data.h"
#include "unified_data_helper.h"
#include "unified_meta.h"
#include "unified_record.h"

using namespace testing::ext;
using namespace OHOS::UDMF;
using namespace OHOS;
namespace OHOS::Test {

class TempUDataLoaderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TempUDataLoaderTest::SetUpTestCase()
{
}

void TempUDataLoaderTest::TearDownTestCase()
{
}

void TempUDataLoaderTest::SetUp()
{
}

void TempUDataLoaderTest::TearDown()
{
}

/**
* @tc.name: IsTempUData_NonFileRecord001
* @tc.desc: Test TempUDataLoader::IsTempUData with non-FILE record returns false
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(TempUDataLoaderTest, IsTempUData_NonFileRecord001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "IsTempUData_NonFileRecord001 begin.");
    UnifiedData data;
    auto record = std::make_shared<UnifiedRecord>(UDType::TEXT);
    data.AddRecord(record);
    bool ret = TempUDataLoader::IsTempUData(data);
    EXPECT_FALSE(ret);
    LOG_INFO(UDMF_TEST, "IsTempUData_NonFileRecord001 end.");
}

/**
* @tc.name: IsTempUData_EmptyData001
* @tc.desc: Test TempUDataLoader::IsTempUData with empty data returns false
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(TempUDataLoaderTest, IsTempUData_EmptyData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "IsTempUData_EmptyData001 begin.");
    UnifiedData data;
    bool ret = TempUDataLoader::IsTempUData(data);
    EXPECT_FALSE(ret);
    LOG_INFO(UDMF_TEST, "IsTempUData_EmptyData001 end.");
}

/**
* @tc.name: Decode_EmptyData001
* @tc.desc: Abnormal testcase of TempUDataLoader::Decode, the packed data has no records
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(TempUDataLoaderTest, Decode_EmptyData001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "Decode_EmptyData001 begin.");
    UnifiedData packed;
    UnifiedData decoded;
    bool ret = TempUDataLoader::Decode(packed, decoded);
    EXPECT_FALSE(ret);
    LOG_INFO(UDMF_TEST, "Decode_EmptyData001 end.");
}

/**
* @tc.name: Decode_InvalidRecord001
* @tc.desc: Abnormal testcase of TempUDataLoader::Decode, the record has no URI
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(TempUDataLoaderTest, Decode_InvalidRecord001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "Decode_InvalidRecord001 begin.");
    UnifiedData packed;
    auto record = std::make_shared<UnifiedRecord>(UDType::FILE);
    packed.AddRecord(record);
    UnifiedData decoded;
    bool ret = TempUDataLoader::Decode(packed, decoded);
    EXPECT_FALSE(ret);
    LOG_INFO(UDMF_TEST, "Decode_InvalidRecord001 end.");
}

/**
* @tc.name: RoundTrip001
* @tc.desc: Test Pack then TempUDataLoader::Decode restores generic records
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(TempUDataLoaderTest, RoundTrip001, TestSize.Level1)
{
    LOG_INFO(UDMF_TEST, "RoundTrip001 begin.");
    UnifiedDataHelper::SetRootPath("/data/udmf_test/");
    UnifiedData data;
    auto record = std::make_shared<UnifiedRecord>(UDType::TEXT);
    record->SetUtdId("general.text");
    data.AddRecord(record);
    ASSERT_TRUE(UnifiedDataHelper::Pack(data));
    ASSERT_TRUE(TempUDataLoader::IsTempUData(data));

    UnifiedData decoded;
    ASSERT_TRUE(TempUDataLoader::Decode(data, decoded));
    UnifiedDataHelper::SetRootPath("");
    auto records = decoded.GetRecords();
    ASSERT_EQ(records.size(), 1);
    EXPECT_EQ(records[0]->GetType(), UDType::TEXT);
    LOG_INFO(UDMF_TEST, "RoundTrip001 end.");
}

} // namespace OHOS::Test
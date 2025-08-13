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
#define LOG_TAG "UtdConcurrentUpdateTest"
#include <gtest/gtest.h>

#include <unistd.h>
#include <thread>

#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"

#include "logger.h"
#include "utd_client.h"
#include "type_descriptor.h"
#include "preset_type_descriptors.h"
#include "utd_graph.h"
#include "custom_utd_store.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UDMF;
using namespace OHOS;

namespace OHOS::Test {
constexpr const int32_t USERID = 100;

class UtdConcurrentUpdateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    void SetNativeToken(const std::string &processName);
};

void UtdConcurrentUpdateTest::SetUpTestCase()
{
}

void UtdConcurrentUpdateTest::TearDownTestCase()
{
}

void UtdConcurrentUpdateTest::SetUp()
{
    SetNativeToken("foundation");
}

void UtdConcurrentUpdateTest::TearDown()
{
}

static constexpr const char *K_TEST_JSON_STR = R"({
    "UniformDataTypeDeclarations": [
        {
            "TypeId": "com.example.thread.image",
            "BelongingToTypes": ["general.image"],
            "FilenameExtensions": [".myImage", ".khImage"],
            "MIMETypes": ["application/myImage", "application/khImage"],
            "Description": "My Image.",
            "ReferenceURL": ""
        },
        {
            "TypeId": "com.example.thread.audio",
            "BelongingToTypes": ["general.audio"],
            "FilenameExtensions": [".myAudio", ".khAudio"],
            "MIMETypes": ["application/myAudio", "application/khAudio"],
            "Description": "My audio.",
            "ReferenceURL": ""
        }
    ]
})";

void UtdConcurrentUpdateTest::SetNativeToken(const std::string &processName)
{
    auto tokenId = AccessTokenKit::GetNativeTokenId(processName);
    SetSelfTokenID(tokenId);
}

std::string ReplaceThread(const std::string& jsonStr, const std::string& newThreadId)
{
    std::string result = jsonStr;
    std::string target = "com.example.thread";
    size_t pos = 0;
    while ((pos = result.find(target, pos)) != std::string::npos) {
        result.replace(pos, target.length(), newThreadId);
        pos += newThreadId.length();
    }
    return result;
}

/**
* @tc.name: MultiThreadUpdate001
* @tc.desc: MultiThread Update
* @tc.type: FUNC
*/
HWTEST_F(UtdConcurrentUpdateTest, MultiThreadUpdate001, TestSize.Level1)
{
    const int numThreads = 8;
    for (int i = 1; i <= numThreads; ++i) {
        UtdClient::GetInstance().UninstallCustomUtds("com.example.thread" + std::to_string(i), USERID);
    }
    std::vector<TypeDescriptorCfg> prevCustomTypeCfgs = CustomUtdStore::GetInstance().GetCustomUtd(false, USERID);
    size_t prevSize = prevCustomTypeCfgs.size();
    
    const int trials = 50;
    for (int i = 0; i < trials; ++i) {
        bool op = (i % 2 == 0);
        auto worker = [op](int threadId) {
            const std::string bundleName = "com.example.thread" + std::to_string(threadId);
            auto jsonStr = ReplaceThread(K_TEST_JSON_STR, bundleName);
            if (op) {
                UtdClient::GetInstance().InstallCustomUtds(bundleName, jsonStr, USERID);
                LOG_INFO(UDMF_CLIENT, "Thread %{public}d Install done", threadId);
            } else {
                UtdClient::GetInstance().UninstallCustomUtds(bundleName, USERID);
                LOG_INFO(UDMF_CLIENT, "Thread %{public}d Uninstall done", threadId);
            }
        };
        std::vector<std::thread> threads;
        for (int j = 1; j <= numThreads; ++j) {
            threads.emplace_back(worker, j);
        }
        for (auto &t : threads) {
            t.join();
        }

        auto customTypeCfgs = CustomUtdStore::GetInstance().GetCustomUtd(false, USERID);
        if (op) {
            EXPECT_EQ(customTypeCfgs.size(), numThreads * 2 + prevSize);
        } else {
            EXPECT_EQ(customTypeCfgs.size(), prevSize);
        }
        for (const auto &cfg : customTypeCfgs) {
            if (std::find(prevCustomTypeCfgs.begin(), prevCustomTypeCfgs.end(), cfg) == prevCustomTypeCfgs.end()) {
                EXPECT_TRUE(cfg.typeId.find("com.example.thread") != std::string::npos);
                EXPECT_TRUE(cfg.belongingToTypes.size() > 0);
                EXPECT_TRUE(cfg.filenameExtensions.size() > 0);
                EXPECT_TRUE(cfg.mimeTypes.size() > 0);
            }
        }
    }
    for (int i = 1; i <= numThreads; ++i) {
        UtdClient::GetInstance().UninstallCustomUtds("com.example.thread" + std::to_string(i), USERID);
    }
    auto customTypeCfgs = CustomUtdStore::GetInstance().GetCustomUtd(false, USERID);
    EXPECT_EQ(customTypeCfgs.size(), prevSize);
};
} // namespace OHOS::Test
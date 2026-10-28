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

#include "virtual_entry_request_coordinator.h"

#include <chrono>
#include <condition_variable>
#include <mutex>

#include "gtest/gtest.h"

using namespace testing::ext;

namespace OHOS::UDMF {
class VirtualEntryRequestCoordinatorTest : public testing::Test {
};

/**
 * @tc.name: TryAcquire_ReadLimitReached_RejectExcessRequest
 * @tc.desc: Verify only the configured number of read callbacks can wait concurrently.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, TryAcquire_ReadLimitReached_RejectExcessRequest, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator(2, std::chrono::milliseconds(10));

    EXPECT_TRUE(coordinator.TryAcquire());
    EXPECT_TRUE(coordinator.TryAcquire());
    EXPECT_FALSE(coordinator.TryAcquire());
    coordinator.Release();
    EXPECT_TRUE(coordinator.TryAcquire());
    coordinator.Release();
    coordinator.Release();
}

/**
 * @tc.name: Wait_RequestNotCompleted_ReturnTimeout
 * @tc.desc: Verify an unfinished provider callback stops waiting at the configured deadline.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, Wait_RequestNotCompleted_ReturnTimeout, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator(1, std::chrono::milliseconds(1));
    std::mutex mutex;
    std::condition_variable condition;
    std::unique_lock<std::mutex> lock(mutex);

    EXPECT_FALSE(coordinator.Wait(condition, lock, [] { return false; }));
}

/**
 * @tc.name: Wait_RequestAlreadyCompleted_ReturnImmediately
 * @tc.desc: Verify a completed provider callback does not wait for the deadline.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, Wait_RequestAlreadyCompleted_ReturnImmediately, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator(1, std::chrono::seconds(1));
    std::mutex mutex;
    std::condition_variable condition;
    std::unique_lock<std::mutex> lock(mutex);

    EXPECT_TRUE(coordinator.Wait(condition, lock, [] { return true; }));
}
} // namespace OHOS::UDMF

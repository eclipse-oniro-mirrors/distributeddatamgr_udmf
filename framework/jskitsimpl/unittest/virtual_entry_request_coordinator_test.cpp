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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

using namespace testing::ext;

namespace OHOS::UDMF {
namespace {
struct ReaderStats {
    std::atomic<size_t> inFlight{ 0 };
    std::atomic<size_t> violations{ 0 };
    std::atomic<size_t> accepted{ 0 };
};

void RunReader(const std::shared_future<void> &start, VirtualEntryRequestCoordinator &coordinator, size_t quota,
    ReaderStats &stats)
{
    start.wait();
    constexpr size_t attemptCount = 2000;
    for (size_t attempt = 0; attempt < attemptCount; ++attempt) {
        if (!coordinator.TryAcquire()) {
            continue;
        }
        ++stats.accepted;
        if (++stats.inFlight > quota) {
            ++stats.violations;
        }
        std::this_thread::yield();
        --stats.inFlight;
        coordinator.Release();
    }
}

void ReleaseSlots(const std::shared_future<void> &start, VirtualEntryRequestCoordinator &coordinator, size_t count)
{
    start.wait();
    for (size_t slot = 0; slot < count; ++slot) {
        coordinator.Release();
    }
}
} // namespace

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

/**
 * @tc.name: TryAcquire_ZeroLimit_RejectEveryRequest
 * @tc.desc: Verify zero capacity cannot be increased by releasing an unacquired slot.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, TryAcquire_ZeroLimit_RejectEveryRequest, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator(0);
    EXPECT_FALSE(coordinator.TryAcquire());
    coordinator.Release();
    EXPECT_FALSE(coordinator.TryAcquire());
}

/**
 * @tc.name: Release_EmptyCounter_PreserveAvailableCapacity
 * @tc.desc: Verify repeated releases at zero do not underflow or create extra slots.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, Release_EmptyCounter_PreserveAvailableCapacity, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator(1);
    coordinator.Release();
    coordinator.Release();
    EXPECT_TRUE(coordinator.TryAcquire());
    EXPECT_FALSE(coordinator.TryAcquire());
    coordinator.Release();
    coordinator.Release();
    EXPECT_TRUE(coordinator.TryAcquire());
    EXPECT_FALSE(coordinator.TryAcquire());
    coordinator.Release();
}

/**
 * @tc.name: TryAcquire_DefaultLimit_AllowExactlyEightReads
 * @tc.desc: Verify the default process quota and its reuse after every slot is released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, TryAcquire_DefaultLimit_AllowExactlyEightReads, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator;
    for (size_t index = 0; index < 8; ++index) {
        EXPECT_TRUE(coordinator.TryAcquire());
    }
    EXPECT_FALSE(coordinator.TryAcquire());
    for (size_t index = 0; index < 8; ++index) {
        coordinator.Release();
    }
    EXPECT_TRUE(coordinator.TryAcquire());
    coordinator.Release();
}

/**
 * @tc.name: Wait_CompletionNotified_WakeBeforeDeadline
 * @tc.desc: Verify completion under the request lock wakes a waiting callback without polling.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, Wait_CompletionNotified_WakeBeforeDeadline, TestSize.Level0)
{
    VirtualEntryRequestCoordinator coordinator(1, std::chrono::seconds(2));
    std::mutex mutex;
    std::condition_variable condition;
    std::promise<void> waiting;
    bool completed = false;
    bool result = false;
    std::thread reader([&coordinator, &condition, &mutex, &waiting, &result, &completed] {
        std::unique_lock<std::mutex> lock(mutex);
        waiting.set_value();
        result = coordinator.Wait(condition, lock, [&completed] { return completed; });
    });
    waiting.get_future().wait();
    {
        std::lock_guard<std::mutex> lock(mutex);
        completed = true;
    }
    condition.notify_all();
    reader.join();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TryAcquire_ConcurrentReaders_RespectQuotaAndReleaseAllSlots
 * @tc.desc: Verify contending reads cannot exceed the configured quota or leak slots.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, TryAcquire_ConcurrentReaders_RespectQuotaAndReleaseAllSlots,
    TestSize.Level0)
{
    constexpr size_t quota = 3;
    VirtualEntryRequestCoordinator coordinator(quota);
    std::promise<void> begin;
    auto start = begin.get_future().share();
    ReaderStats stats;
    std::vector<std::thread> readers;
    for (size_t index = 0; index < 16; ++index) {
        readers.emplace_back(RunReader, std::cref(start), std::ref(coordinator), quota, std::ref(stats));
    }
    begin.set_value();
    for (auto &reader : readers) {
        reader.join();
    }
    EXPECT_GT(stats.accepted.load(), 0u);
    EXPECT_EQ(stats.violations.load(), 0u);
    EXPECT_EQ(stats.inFlight.load(), 0u);
    for (size_t index = 0; index < quota; ++index) {
        EXPECT_TRUE(coordinator.TryAcquire());
    }
    EXPECT_FALSE(coordinator.TryAcquire());
    for (size_t index = 0; index < quota; ++index) {
        coordinator.Release();
    }
}

/**
 * @tc.name: Release_ContendingReleases_ReturnEverySlot
 * @tc.desc: Verify concurrent decrements retry failed comparisons and preserve exact capacity.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryRequestCoordinatorTest, Release_ContendingReleases_ReturnEverySlot, TestSize.Level0)
{
    constexpr size_t threads = 32;
    constexpr size_t slotsPerThread = 128;
    constexpr size_t capacity = threads * slotsPerThread;
    VirtualEntryRequestCoordinator coordinator(capacity);
    for (size_t index = 0; index < capacity; ++index) {
        ASSERT_TRUE(coordinator.TryAcquire());
    }
    std::promise<void> begin;
    auto start = begin.get_future().share();
    std::vector<std::thread> releasers;
    for (size_t index = 0; index < threads; ++index) {
        releasers.emplace_back(ReleaseSlots, std::cref(start), std::ref(coordinator), slotsPerThread);
    }
    begin.set_value();
    for (auto &releaser : releasers) {
        releaser.join();
    }
    for (size_t index = 0; index < capacity; ++index) {
        EXPECT_TRUE(coordinator.TryAcquire());
    }
    EXPECT_FALSE(coordinator.TryAcquire());
    for (size_t index = 0; index < capacity; ++index) {
        coordinator.Release();
    }
}
} // namespace OHOS::UDMF

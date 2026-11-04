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

#ifndef UDMF_VIRTUAL_ENTRY_REQUEST_COORDINATOR_H
#define UDMF_VIRTUAL_ENTRY_REQUEST_COORDINATOR_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace OHOS::UDMF {
class VirtualEntryRequestCoordinator final {
public:
    // Limit all provider instances in one application process so pending Binder
    // calls cannot occupy the complete application Binder thread pool.
    static constexpr size_t defaultMaxConcurrentReads = 8;
    // Each provider read loads at most one 5 MiB block. Concurrent requests are
    // bounded so large virtual files cannot occupy the complete Binder thread pool.
    static constexpr std::chrono::milliseconds defaultTimeout = std::chrono::seconds(30);

    explicit VirtualEntryRequestCoordinator(size_t maxConcurrentReads = defaultMaxConcurrentReads,
        std::chrono::milliseconds timeout = defaultTimeout)
        : maxConcurrentReads_(maxConcurrentReads), timeout_(timeout)
    {
    }

    bool TryAcquire()
    {
        size_t current = activeReads_.load(std::memory_order_relaxed);
        while (current < maxConcurrentReads_) {
            size_t expected = current;
            if (activeReads_.compare_exchange_weak(
                expected, current + 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                return true;
            }
            current = expected;
        }
        return false;
    }

    void Release()
    {
        size_t current = activeReads_.load(std::memory_order_relaxed);
        while (current != 0) {
            size_t expected = current;
            if (activeReads_.compare_exchange_weak(
                expected, current - 1, std::memory_order_release, std::memory_order_relaxed)) {
                return;
            }
            current = expected;
        }
    }

    template<typename Predicate>
    bool Wait(std::condition_variable &condition, std::unique_lock<std::mutex> &lock, Predicate predicate) const
    {
        return condition.wait_for(lock, timeout_, predicate);
    }

private:
    const size_t maxConcurrentReads_;
    const std::chrono::milliseconds timeout_;
    std::atomic<size_t> activeReads_{ 0 };
};
} // namespace OHOS::UDMF

#endif // UDMF_VIRTUAL_ENTRY_REQUEST_COORDINATOR_H

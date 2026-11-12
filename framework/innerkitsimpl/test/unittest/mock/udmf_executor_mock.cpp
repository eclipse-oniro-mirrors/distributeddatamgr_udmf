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

#include "udmf_executor_mock.h"

#include <algorithm>
namespace OHOS::UDMF {
std::deque<AuthTaskScheduler::Task> AuthTaskScheduler::tasks_;
UdmfTaskId AuthTaskScheduler::next_ = 1;
UdmfTaskId AuthTaskScheduler::Add(UdmfTask task)
{
    auto id = next_++;
    tasks_.push_back({ id, std::move(task) });
    return id;
}
bool AuthTaskScheduler::Remove(UdmfTaskId id)
{
    auto it = std::find_if(tasks_.begin(), tasks_.end(), [id](const auto &task) { return task.id == id; });
    if (it == tasks_.end()) {
        return false;
    }
    tasks_.erase(it);
    return true;
}
bool AuthTaskScheduler::RunNext()
{
    if (tasks_.empty()) {
        return false;
    }
    auto task = std::move(tasks_.front().run);
    tasks_.pop_front();
    task();
    return true;
}
bool AuthTaskScheduler::RunLast()
{
    if (tasks_.empty()) {
        return false;
    }
    auto task = std::move(tasks_.back().run);
    tasks_.pop_back();
    task();
    return true;
}
void AuthTaskScheduler::Reset()
{
    tasks_.clear();
}
UdmfExecutor::UdmfExecutor(size_t max, size_t min) : executor_(max, min)
{
}
UdmfTaskId UdmfExecutor::Execute(UdmfTask task)
{
    return AuthTaskScheduler::Add(std::move(task));
}
UdmfTaskId UdmfExecutor::Schedule(UdmfDuration, UdmfTask task)
{
    return AuthTaskScheduler::Add(std::move(task));
}
bool UdmfExecutor::Remove(UdmfTaskId id, bool)
{
    return AuthTaskScheduler::Remove(id);
}
} // namespace OHOS::UDMF

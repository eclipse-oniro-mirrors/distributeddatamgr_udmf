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

#ifndef UDMF_EXECUTOR_MOCK_H
#define UDMF_EXECUTOR_MOCK_H
#include <deque>

#include "udmf_executor.h"
namespace OHOS::UDMF {
// Deterministic executor boundary: tests choose task order without sleeps or
// private client access.
class AuthTaskScheduler {
public:
    static UdmfTaskId Add(UdmfTask task);
    static bool Remove(UdmfTaskId id);
    static bool RunNext();
    static bool RunLast();
    static void Reset();

private:
    struct Task {
        UdmfTaskId id;
        UdmfTask run;
    };
    static std::deque<Task> tasks_;
    static UdmfTaskId next_;
};
} // namespace OHOS::UDMF
#endif

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef UDMF_LIFECYCLE_MANAGER_H
#define UDMF_LIFECYCLE_MANAGER_H

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "clean_after_get.h"
#include "clean_on_startup.h"
#include "clean_on_timeout.h"
#include "executor_pool.h"
#include "lifecycle_policy.h"

namespace OHOS {
namespace UDMF {
class LifeCycleManager {
public:
    static LifeCycleManager &GetInstance();
    Status DeleteOnGet(const UnifiedKey &key);
    Status DeleteOnStart();
    Status DeleteOnSchedule();

private:
    static std::shared_ptr<ExecutorPool> executorPool_;
    static std::unordered_map<std::string, std::shared_ptr<LifeCyclePolicy>> intentionPolicyMap_;
    static std::shared_ptr<LifeCyclePolicy> GetPolicy(const std::string &intention);
    static Status DeleteOnTimeout();
};
} // namespace UDMF
} // namespace OHOS
#endif //UDMF_LIFECYCLE_MANAGER_H

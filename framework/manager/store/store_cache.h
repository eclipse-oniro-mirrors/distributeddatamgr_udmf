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

#ifndef UDMF_STORE_CACHE_H
#define UDMF_STORE_CACHE_H

#include <memory>

#include "concurrent_map.h"
#include "store.h"
#include "unified_meta.h"

namespace OHOS {
namespace UDMF {
class StoreCache {
public:
    std::shared_ptr<Store> GetStore(std::string intention);

private:
    ConcurrentMap<std::string, std::shared_ptr<Store>> stores_;
};
} // namespace UDMF
} // namespace OHOS
#endif //UDMF_STORE_CACHE_H

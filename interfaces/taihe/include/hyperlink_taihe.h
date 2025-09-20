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

#ifndef UDMF_HYPERLINK_TAIHE_H
#define UDMF_HYPERLINK_TAIHE_H

#include "link.h"
#include "ohos.data.unifiedDataChannel.proj.hpp"
#include "ohos.data.unifiedDataChannel.impl.hpp"

namespace taiheChannel = ohos::data::unifiedDataChannel;
namespace OHOS {
namespace UDMF {
class HyperlinkTaihe {
public:
    HyperlinkTaihe();

    ::taihe::string GetType();
    ::taiheChannel::ValueType GetValue();
    ::taihe::optional<::taihe::map<::taihe::string, ::taihe::string>> GetDetails();
    void SetDetails(const ::taihe::map_view<::taihe::string, ::taihe::string> &details);
    void SetUrl(const ::taihe::string_view &url);
    ::taihe::string GetUrl();
    void SetDescription(const ::taihe::string_view &description);
    ::taihe::string GetDescription();
    int64_t GetInner();

    std::shared_ptr<Link> value_;
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_HYPERLINK_TAIHE_H
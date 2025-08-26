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

#define LOG_TAG "UDMF_DEFINED_PIXELMAP"

#include <dlfcn.h>

#include "defined_pixelmap_taihe.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "logger.h"
#include "system_defined_pixelmap_napi.h"
#include "taihe_common_utils.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace UDMF {
using CreateInstance = napi_value (*)(napi_env, std::shared_ptr<SystemDefinedPixelMap>);
SystemDefinedPixelMapTaihe::SystemDefinedPixelMapTaihe()
{
    this->value_ = std::make_shared<SystemDefinedPixelMap>();
}

SystemDefinedPixelMapTaihe::SystemDefinedPixelMapTaihe(std::shared_ptr<SystemDefinedPixelMap> value)
{
    this->value_ = value;
}

::taihe::string SystemDefinedPixelMapTaihe::GetType()
{
    return ::taihe::string(UtdUtils::GetUtdIdFromUtdEnum(this->value_->GetType()));
}

::taiheChannel::ValueType SystemDefinedPixelMapTaihe::GetValue()
{
    return ConvertValueType(this->value_->GetValue());
}

::taihe::optional<::taihe::map<::taihe::string, ::taiheChannel::DetailsValue>> SystemDefinedPixelMapTaihe::GetDetails()
{
    return ::taihe::optional<::taihe::map<::taihe::string, ::taiheChannel::DetailsValue>>::make(
        ConvertUDDetailsToUnion(this->value_->GetDetails()));
}

void SystemDefinedPixelMapTaihe::SetDetails(
    const ::taihe::map_view<::taihe::string, ::taiheChannel::DetailsValue> &details)
{
    UDDetails udmfDetails = ConvertUDDetailsToUnion(details);
    this->value_->SetDetails(udmfDetails);
}

::taihe::optional<::taihe::array<uint8_t>> SystemDefinedPixelMapTaihe::GetRawData()
{
    auto rawData = this->value_->GetRawData();
    return ::taihe::optional<::taihe::array<uint8_t>>::make(
        ::taihe::array<uint8_t>(rawData));
}

void SystemDefinedPixelMapTaihe::SetRawData(const ::taihe::array_view<uint8_t> &rawData)
{
    if (rawData.size() == 0) {
        return;
    }
    std::vector<uint8_t> rawDataVec(rawData.begin(), rawData.end());
    this->value_->SetRawData(rawDataVec);
}

int64_t SystemDefinedPixelMapTaihe::GetInner()
{
    return reinterpret_cast<int64_t>(this);
}

::taiheChannel::SystemDefinedPixelMapInner CreateSystemDefinedPixelMap()
{
    return taihe::make_holder<SystemDefinedPixelMapTaihe, ::taiheChannel::SystemDefinedPixelMapInner>();
}

::taiheChannel::SystemDefinedPixelMapInner SystemDefinedPixelMapTransferStaticImpl(uintptr_t input)
{
    ani_object esValue = reinterpret_cast<ani_object>(input);
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), esValue, &nativePtr) || nativePtr == nullptr) {
        LOG_ERROR(UDMF_ANI, "unwrap esvalue failed");
        return taihe::make_holder<SystemDefinedPixelMapTaihe, ::taiheChannel::SystemDefinedPixelMapInner>();
    }
    auto pixelMapNapi = reinterpret_cast<SystemDefinedPixelMapNapi *>(nativePtr);
    if (pixelMapNapi == nullptr || pixelMapNapi->value_ == nullptr) {
        LOG_ERROR(UDMF_ANI, "cast SystemDefinedPixelMapNapi failed");
        return taihe::make_holder<SystemDefinedPixelMapTaihe, ::taiheChannel::SystemDefinedPixelMapInner>();
    }
    return taihe::make_holder<SystemDefinedPixelMapTaihe,
        ::taiheChannel::SystemDefinedPixelMapInner>(pixelMapNapi->value_);
}

uintptr_t SystemDefinedPixelMapTransferDynamicImpl(::taiheChannel::weak::SystemDefinedPixelMapInner input)
{
    auto pixelMapPtr = input->GetInner();
    auto pixelMapInnerPtr = reinterpret_cast<SystemDefinedPixelMapTaihe *>(pixelMapPtr);
    if (pixelMapInnerPtr == nullptr) {
        LOG_ERROR(UDMF_ANI, "cast native pointer failed");
        return 0;
    }
    std::shared_ptr<SystemDefinedPixelMap> systemDefinedPixelMap = pixelMapInnerPtr->value_;
    pixelMapInnerPtr = nullptr;
    napi_env jsenv;
    if (!arkts_napi_scope_open(taihe::get_env(), &jsenv)) {
        LOG_ERROR(UDMF_ANI, "arkts_napi_scope_open failed");
        return 0;
    }
    auto handle = dlopen(NEW_INSTANCE_LIB.c_str(), RTLD_NOW);
    if (handle == nullptr) {
        LOG_ERROR(UDMF_ANI, "dlopen failed");
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    }
    CreateInstance newInstance = reinterpret_cast<CreateInstance>(dlsym(handle, "GetEtsSysPixelMap"));
    if (newInstance == nullptr) {
        LOG_ERROR(UDMF_ANI, "dlsym get func failed, %{public}s", dlerror());
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        dlclose(handle);
        return 0;
    }
    napi_value instance = newInstance(jsenv, systemDefinedPixelMap);
    dlclose(handle);
    if (instance == nullptr) {
        LOG_ERROR(UDMF_ANI, "instance is nullptr");
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    }
    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsenv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    return result;
}
} // namespace UDMF
} // namespace OHOS

TH_EXPORT_CPP_API_CreateSystemDefinedPixelMap(OHOS::UDMF::CreateSystemDefinedPixelMap);
TH_EXPORT_CPP_API_SystemDefinedPixelMapTransferStaticImpl(OHOS::UDMF::SystemDefinedPixelMapTransferStaticImpl);
TH_EXPORT_CPP_API_SystemDefinedPixelMapTransferDynamicImpl(OHOS::UDMF::SystemDefinedPixelMapTransferDynamicImpl);
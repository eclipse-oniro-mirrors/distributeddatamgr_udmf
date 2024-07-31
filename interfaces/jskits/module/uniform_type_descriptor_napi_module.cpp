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
#define LOG_TAG "UDMFUniformTypModule"
#include "uniform_type_descriptor_napi.h"
#include "type_descriptor_napi.h"

using namespace OHOS::UDMF;

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    OHOS::UDMF::UniformTypeDescriptorNapi::UniformTypeDescriptorInit(env, exports);
    napi_status status =
        napi_set_named_property(env, exports, "TypeDescriptor", OHOS::UDMF::TypeDescriptorNapi::Constructor(env));
    LOG_INFO(UDMF_KITS_NAPI, "init TypeDescriptor %{public}d", status);
    return exports;
}
EXTERN_C_END

static napi_module _module = { .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "data.uniformTypeDescriptor",
    .nm_priv = ((void *)0),
    .reserved = { 0 } };

extern "C" __attribute__((constructor)) void RegisterUDMFUnifiedDataModule(void)
{
    napi_module_register(&_module);
    LOG_INFO(UDMF_KITS_NAPI, "module register data.uniformTypeDescriptor");
}

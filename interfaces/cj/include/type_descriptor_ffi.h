/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UDMF_TYPE_DESCRIPTOR_FFI_H
#define UDMF_TYPE_DESCRIPTOR_FFI_H

#include <cstdint>
#include "ffi_remote_data.h"
#include "cj_common_ffi.h"

#include "type_descriptor_impl.h"

namespace OHOS {
namespace UDMF {
extern "C" {
    FFI_EXPORT char *FfiUDMFUniformTypeDescriptorGetTypeId(int64_t typeDescriptorID);
    FFI_EXPORT CArrString FfiUDMFUniformTypeDescriptorGetBelongingToTypes(int64_t typeDescriptorID);
    FFI_EXPORT char *FfiUDMFUniformTypeDescriptorGetDescription(int64_t typeDescriptorID);
    FFI_EXPORT char *FfiUDMFUniformTypeDescriptorGetReferenceURL(int64_t typeDescriptorID);
    FFI_EXPORT char *FfiUDMFUniformTypeDescriptorGetIconFile(int64_t typeDescriptorID);
    FFI_EXPORT CArrString FfiUDMFUniformTypeDescriptorGetFilenameExtensions(int64_t typeDescriptorID);
    FFI_EXPORT CArrString FfiUDMFUniformTypeDescriptorGetMimeTypes(int64_t typeDescriptorID);
    FFI_EXPORT bool FfiUDMFUniformTypeDescriptorBelongsTo(int64_t typeDescriptorID, const char *type);
    FFI_EXPORT bool FfiUDMFUniformTypeDescriptorIsLowerLevelType(int64_t typeDescriptorID, const char *type);
    FFI_EXPORT bool FfiUDMFUniformTypeDescriptorIsHigherLevelType(int64_t typeDescriptorID, const char *type);
    FFI_EXPORT bool FfiUDMFUniformTypeDescriptorEquals(int64_t thisTypeDescriptorID, int64_t thatTypeDescriptorID);
}
}
}

#endif
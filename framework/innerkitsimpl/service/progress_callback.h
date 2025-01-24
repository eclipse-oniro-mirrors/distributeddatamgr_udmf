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

#ifndef OHOS_PROGRESS_CALLBACK_H
#define OHOS_PROGRESS_CALLBACK_H

#include <iremote_broker.h>
#include <iremote_stub.h>

namespace OHOS {
namespace UDMF {
class IProgressSignal : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.miscservices.dialog.callback");
    virtual void HandleProgressSignalValue(MessageParcel &data) = 0;
};

class ProgressSignalStub : public IRemoteStub<IProgressSignal> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
};

class ProgressSignalCallback : public ProgressSignalStub {
public:
    void HandleProgressSignalValue(MessageParcel &data) override;
};
} // namespace UDMF
} // namespace OHOS
#endif // OHOS_PROGRESS_CALLBACK_H
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef RAG_AGENT_CHATLLM_NAPI_H
#define RAG_AGENT_CHATLLM_NAPI_H
#include "napi/native_node_api.h"

namespace OHOS {
namespace DataIntelligence {

class RAGAgentChatLLMNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static napi_status InitEnum(napi_env env, napi_value exports);
};
} // namespace DataIntelligence
} // namespace OHOS
#endif //RAG_AGENT_CHATLLM_NAPI_H

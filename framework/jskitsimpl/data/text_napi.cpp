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
#define LOG_TAG "TextNapi"
#include "text_napi.h"

#include "text.h"
#include "napi_data_utils.h"
#include "napi_error_utils.h"
#include "napi_queue.h"
#include "unified_record_napi.h"

namespace OHOS {
namespace UDMF {
napi_value TextNapi::Constructor(napi_env env)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi");
    napi_property_descriptor properties[] = {
        /* Text extends UnifiedRecord */
        DECLARE_NAPI_FUNCTION("getType", UnifiedRecordNapi::GetType),
        /* Text properties */
        DECLARE_NAPI_GETTER_SETTER("details", GetDetails, SetDetails),
    };
    size_t count = sizeof(properties) / sizeof(properties[0]);
    return NapiDataUtils::DefineClass(env, "Text", properties, count, TextNapi::New);
}

napi_value TextNapi::New(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi");
    auto ctxt = std::make_shared<ContextBase>();
    std::string type;
    napi_value value = nullptr;
    auto input = [env, ctxt, &type, &value](size_t argc, napi_value* argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc == 0 || argc >= 2, Status::E_INVALID_PARAMETERS, "invalid arguments!");
        if (argc >= 2) {
            ctxt->status = NapiDataUtils::GetValue(env, argv[0], type);
            ASSERT_BUSINESS_ERR(ctxt, ctxt->status == napi_ok, E_INVALID_PARAMETERS, "invalid arguments!");
            value = argv[1];
        }
    };
    ctxt->GetCbInfoSync(env, info, input);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS, "invalid arguments!");

    auto *text = new (std::nothrow) TextNapi();
    ASSERT_ERR(ctxt->env, text != nullptr, Status::E_ERROR, "no memory for text!");
    if(value != nullptr) {
        ASSERT_ERR(ctxt->env, type == UD_TYPE_MAP.at(UDType::TEXT), Status::E_ERROR, "invalid arguments!");
        text->value_ = std::static_pointer_cast<Text>(UnifiedRecordNapi::GetNativeRecord(ctxt->env, type, value));
    } else {
        text->value_ = std::make_shared<Text>();
    }
    ASSERT_CALL(ctxt->env, napi_wrap(env, ctxt->self, text, Destructor, nullptr, nullptr), text);
    return ctxt->self;
}

void TextNapi::NewInstance(napi_env env, std::shared_ptr<UnifiedRecord> in, napi_value &out)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi");
    ASSERT_CALL_VOID(env, napi_new_instance(env, Constructor(env), 0, nullptr, &out));
    auto *text = new (std::nothrow) TextNapi();
    ASSERT_ERR_VOID(env, text != nullptr, Status::E_ERROR, "no memory for text!");
    text->value_ = std::static_pointer_cast<Text>(in);
    ASSERT_CALL_DELETE(env, napi_wrap(env, out, text, Destructor, nullptr, nullptr), text);
}

void TextNapi::Destructor(napi_env env, void *data, void *hint)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi finalize.");
    auto *text = static_cast<TextNapi *>(data);
    ASSERT_VOID(text != nullptr, "finalize null!");
    delete text;
}

TextNapi *TextNapi::GetText(napi_env env, napi_callback_info info, std::shared_ptr<ContextBase> ctxt)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi");
    ctxt->GetCbInfoSync(env, info);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS, "invalid arguments!");
    return static_cast<TextNapi *>(ctxt->native);
}

napi_value TextNapi::GetDetails(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi");
    auto ctxt = std::make_shared<ContextBase>();
    auto text = GetText(env, info, ctxt);
    ASSERT_ERR(
        ctxt->env, (text != nullptr && text->value_ != nullptr), Status::E_INVALID_PARAMETERS, "invalid object!");
    ctxt->status = NapiDataUtils::SetValue(env, text->value_->GetDetails(), ctxt->output);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS, "set details failed!");
    return ctxt->output;
}

napi_value TextNapi::SetDetails(napi_env env, napi_callback_info info)
{
    LOG_DEBUG(UDMF_KITS_NAPI, "TextNapi");
    auto ctxt = std::make_shared<ContextBase>();
    UDDetails details;
    auto input = [env, ctxt, &details](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::E_INVALID_PARAMETERS, "invalid arguments!");
        ctxt->status = NapiDataUtils::GetValue(env, argv[0], details);
        ASSERT_BUSINESS_ERR(ctxt, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS, "invalid arguments!");
    };
    ctxt->GetCbInfoSync(env, info, input);
    ASSERT_ERR(ctxt->env, ctxt->status == napi_ok, Status::E_INVALID_PARAMETERS, "invalid arguments!");
    auto text = static_cast<TextNapi *>(ctxt->native);
    ASSERT_ERR(
        ctxt->env, (text != nullptr && text->value_ != nullptr), Status::E_INVALID_PARAMETERS, "invalid object!");
    text->value_->SetDetails(details);
    return nullptr;
}
} // namespace UDMF
} // namespace OHOS
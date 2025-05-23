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

#ifndef UDMF_NAPI_QUEUE_H
#define UDMF_NAPI_QUEUE_H

#include <functional>
#include <memory>
#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_error_utils.h"

namespace OHOS {
namespace UDMF {
using NapiCbInfoParser = std::function<void(size_t argc, napi_value *argv)>;
using NapiAsyncExecute = std::function<void(void)>;
using NapiAsyncComplete = std::function<void(napi_value &)>;
static constexpr size_t ARGC_MAX = 6;
struct ContextBase {
    virtual ~ContextBase();
    void GetCbInfo(
        napi_env env, napi_callback_info info, NapiCbInfoParser parse = NapiCbInfoParser(), bool sync = false);

    inline void GetCbInfoSync(napi_env env, napi_callback_info info, const NapiCbInfoParser &parse = NapiCbInfoParser())
    {
        /* sync = true, means no callback, not AsyncWork. */
        GetCbInfo(env, info, parse, true);
    }

    napi_env env = nullptr;
    napi_value output = nullptr;
    napi_status status = napi_invalid_arg;
    std::string error;
    int32_t jsCode = 0;
    bool isThrowError = false;

    napi_value self = nullptr;
    void *native = nullptr;

private:
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_ref selfRef = nullptr;

    NapiAsyncExecute execute = nullptr;
    NapiAsyncComplete complete = nullptr;
    std::shared_ptr<ContextBase> hold; /* cross thread data */

    friend class NapiQueue;
};

/* check condition related to argc/argv, return and logging. */
#define ASSERT_ARGS(ctxt, condition, message)                                    \
    do {                                                                         \
        if (!(condition)) {                                                      \
            (ctxt)->status = napi_invalid_arg;                                   \
            (ctxt)->error = std::string(message);                                \
            LOG_ERROR(UDMF_KITS_NAPI, "test (" #condition ") failed: " message); \
            return;                                                              \
        }                                                                        \
    } while (0)

#define ASSERT_STATUS(ctxt, message)                                                      \
    do {                                                                                  \
        if ((ctxt)->status != napi_ok) {                                                  \
            (ctxt)->error = std::string(message);                                         \
            LOG_ERROR(UDMF_KITS_NAPI, "test (ctxt->status == napi_ok) failed: " message); \
            return;                                                                       \
        }                                                                                 \
    } while (0)

/* check condition, return and logging if condition not true. */
#define ASSERT(condition, message, retVal)                                       \
    do {                                                                         \
        if (!(condition)) {                                                      \
            LOG_ERROR(UDMF_KITS_NAPI, "test (" #condition ") failed: " message); \
            return retVal;                                                       \
        }                                                                        \
    } while (0)

#define ASSERT_VOID(condition, message)                                          \
    do {                                                                         \
        if (!(condition)) {                                                      \
            LOG_ERROR(UDMF_KITS_NAPI, "test (" #condition ") failed: " message); \
            return;                                                              \
        }                                                                        \
    } while (0)

#define ASSERT_FALSE(condition, message)                                         \
    do {                                                                         \
        if (!(condition)) {                                                      \
            LOG_ERROR(UDMF_KITS_NAPI, "test (" #condition ") failed: " message); \
            return false;                                                        \
        }                                                                        \
    } while (0)

#define ASSERT_NULL(condition, message) ASSERT(condition, message, nullptr)

#define ASSERT_CALL(env, theCall, object)    \
    do {                                     \
        if ((theCall) != napi_ok) {          \
            delete (object);                 \
            GET_AND_THROW_LAST_ERROR((env)); \
            return nullptr;                  \
        }                                    \
    } while (0)

#define ASSERT_CALL_DELETE(env, theCall, object) \
    do {                                         \
        if ((theCall) != napi_ok) {              \
            delete (object);                     \
            GET_AND_THROW_LAST_ERROR((env));     \
            return;                              \
        }                                        \
    } while (0)

#define ASSERT_CALL_VOID(env, theCall)       \
    do {                                     \
        if ((theCall) != napi_ok) {          \
            GET_AND_THROW_LAST_ERROR((env)); \
            return;                          \
        }                                    \
    } while (0)

#define ASSERT_CALL_DELETE_STATUS(env, theCall, object) \
    do {                                                \
        napi_status status = (theCall);                 \
        if (status != napi_ok) {                        \
            delete (object);                            \
            GET_AND_THROW_LAST_ERROR((env));            \
            return status;                              \
        }                                               \
    } while (0)

#define ASSERT_CALL_STATUS(env, theCall)     \
    do {                                     \
        napi_status status = (theCall);      \
        if (status != napi_ok) {             \
            GET_AND_THROW_LAST_ERROR((env)); \
            return status;                   \
        }                                    \
    } while (0)

#define ASSERT_WITH_ERRCODE(ctxt, condition, errcode, message)                                     \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            (ctxt)->status = napi_generic_failure;                                                 \
            GenerateNapiError(errcode, (ctxt)->jsCode, (ctxt)->error);                             \
            LOG_ERROR(UDMF_KITS_NAPI, "test (" #condition ") failed: " message);                   \
            return;                                                                                \
        }                                                                                          \
    } while (0)

class NapiQueue {
public:
    static napi_value AsyncWork(napi_env env, std::shared_ptr<ContextBase> ctxt, const std::string &name,
        NapiAsyncExecute execute = NapiAsyncExecute(), NapiAsyncComplete complete = NapiAsyncComplete());

private:
    enum {
        /* AsyncCallback / Promise output result index  */
        RESULT_ERROR = 0,
        RESULT_DATA = 1,
        RESULT_ALL = 2
    };

    struct AsyncContext {
        std::shared_ptr<ContextBase> ctxt;
        NapiAsyncExecute execute = nullptr;
        NapiAsyncComplete complete = nullptr;
        napi_deferred deferred = nullptr;
        napi_async_work work = nullptr;
    };

    static void GenerateOutput(ContextBase *ctxt);

    static void onExecute(napi_env env, void *data);
    static void onComplete(napi_env env, napi_status status, void *data);
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_NAPI_QUEUE_H

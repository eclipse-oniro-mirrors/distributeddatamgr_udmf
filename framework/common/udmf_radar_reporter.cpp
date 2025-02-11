/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "UdmfRadarReporter"

#include "udmf_radar_reporter.h"

namespace OHOS {
namespace UDMF {
using namespace RadarReporter;
void RadarReporterAdapter::ReportNormal(
    std::string func, int32_t scene, int32_t stage, int32_t stageRes, int32_t state)
{
    struct HiSysEventParam params[] = {
        { .name = { "ORG_PKG" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(ORG_PKG) },
            .arraySize = 0 },
        { .name = { "FUNC" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(func.c_str()) },
            .arraySize = 0 },
        { .name = { "BIZ_SCENE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = scene },
            .arraySize = 0 },
        { .name = { "BIZ_STAGE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stage },
            .arraySize = 0 },
        { .name = { "STAGE_RES" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stageRes },
            .arraySize = 0 },
        { .name = { "BIZ_STATE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = state },
            .arraySize = 0 }
    };
    OH_HiSysEvent_Write(
        DOMAIN,
        EVENT_NAME,
        HISYSEVENT_BEHAVIOR,
        params,
        sizeof(params) / sizeof(params[0])
    );
}

void RadarReporterAdapter::ReportNormal(std::string func, int32_t scene, int32_t stage, int32_t stageRes)
{
    struct HiSysEventParam params[] = {
        { .name = { "ORG_PKG" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(ORG_PKG) },
            .arraySize = 0 },
        { .name = { "FUNC" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(func.c_str()) },
            .arraySize = 0 },
        { .name = { "BIZ_SCENE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = scene },
            .arraySize = 0 },
        { .name = { "BIZ_STAGE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stage },
            .arraySize = 0 },
        { .name = { "STAGE_RES" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stageRes },
            .arraySize = 0 }
    };
    OH_HiSysEvent_Write(
        DOMAIN,
        EVENT_NAME,
        HISYSEVENT_BEHAVIOR,
        params,
        sizeof(params) / sizeof(params[0])
    );
}

void RadarReporterAdapter::ReportFail(
    std::string func, int32_t scene, int32_t stage, int32_t stageRes, int32_t errorCode, int32_t state)
{
    struct HiSysEventParam params[] = {
        { .name = { "ORG_PKG" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(ORG_PKG) },
            .arraySize = 0 },
        { .name = { "FUNC" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(func.c_str()) },
            .arraySize = 0 },
        { .name = { "BIZ_SCENE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = scene },
            .arraySize = 0 },
        { .name = { "BIZ_STAGE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stage },
            .arraySize = 0 },
        { .name = { "STAGE_RES" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stageRes },
            .arraySize = 0 },
        { .name = { "ERROR_CODE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = errorCode },
            .arraySize = 0 },
        { .name = { "BIZ_STATE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = state },
            .arraySize = 0 }
    };
    OH_HiSysEvent_Write(
        DOMAIN,
        EVENT_NAME,
        HISYSEVENT_BEHAVIOR,
        params,
        sizeof(params) / sizeof(params[0])
    );
}

void RadarReporterAdapter::ReportFail(
    std::string func, int32_t scene, int32_t stage, int32_t stageRes, int32_t errorCode)
{
    struct HiSysEventParam params[] = {
        { .name = { "ORG_PKG" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(ORG_PKG) },
            .arraySize = 0 },
        { .name = { "FUNC" },
            .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(func.c_str()) },
            .arraySize = 0 },
        { .name = { "BIZ_SCENE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = scene },
            .arraySize = 0 },
        { .name = { "BIZ_STAGE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stage },
            .arraySize = 0 },
        { .name = { "STAGE_RES" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = stageRes },
            .arraySize = 0 },
        { .name = { "ERROR_CODE" },
            .t = HISYSEVENT_INT32,
            .v = { .i32 = errorCode },
            .arraySize = 0 }
    };
    OH_HiSysEvent_Write(
        DOMAIN,
        EVENT_NAME,
        HISYSEVENT_BEHAVIOR,
        params,
        sizeof(params) / sizeof(params[0])
    );
}
}
}

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

#include "udmf_client_fuzzer.h"

#include <unistd.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "udmf_client.h"
#include "text.h"
#include "plain_text.h"
#include "html.h"
#include "link.h"
#include "file.h"
#include "image.h"
#include "video.h"
#include "system_defined_record.h"
#include "system_defined_form.h"
#include "system_defined_appitem.h"
#include "system_defined_pixelmap.h"
#include "udmf_async_client.h"
#include "unified_types.h"

using namespace OHOS;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UDMF;

namespace OHOS {
void AllocHapToken()
{
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "ohos.test.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.test.demo"
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {
            {
                .permissionName = "ohos.permission.test",
                .bundleName = "ohos.test.demo",
                .grantMode = 1,
                .availableLevel = APL_NORMAL,
                .label = "label",
                .labelId = 1,
                .description = "test",
                .descriptionId = 1
            }
        },
        .permStateList = {
            {
                .permissionName = "ohos.permission.test",
                .isGeneral = true,
                .resDeviceID = {"local"},
                .grantStatus = {PermissionState::PERMISSION_GRANTED},
                .grantFlags = {1}
            }
        }
    };
    auto tokenID = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void SetUpTestCase()
{
    AllocHapToken();
}

void TearDown()
{
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void SetNativeToken()
{
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .processName = "msdp_sa",
        .aplStr = "system_core",
    };
    auto tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
}

void SetHapToken()
{
    auto tokenId = AccessTokenKit::GetHapTokenID(100, "ohos.test.demo", 0);
    SetSelfTokenID(tokenId);
}

void SetDataTextFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    UnifiedData unifiedData;
    CustomOption option = {.intention = Intention::UD_INTENTION_BUTT};
    auto text = std::make_shared<Text>();
    UDDetails details;
    details.insert({skey, svalue});
    text->SetDetails(details);
    unifiedData.AddRecord(text);
    std::string key;
    UdmfClient::GetInstance().SetData(option, unifiedData, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataPlainTextFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    UDDetails details1;
    auto plainText1 = std::make_shared<PlainText>();
    details1.insert({skey, svalue});
    plainText1->SetDetails(details1);
    plainText1->SetContent(svalue + "content");
    plainText1->SetAbstract(svalue + "abstract");
    plainText1->GetContent();
    plainText1->GetAbstract();
    data1.AddRecord(plainText1);
    std::string key;
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataHtmlFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto html1 = std::make_shared<Html>();
    UDDetails details1;
    details1.insert({skey, svalue});
    html1->SetDetails(details1);
    html1->SetHtmlContent(svalue + "htmlcontent");
    html1->SetPlainContent(svalue + "plainContent");
    html1->GetHtmlContent();
    html1->GetPlainContent();
    data1.AddRecord(html1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataLinkFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto link1 = std::make_shared<Link>();
    UDDetails details1;
    details1.insert({skey, svalue});
    link1->SetDetails(details1);
    link1->SetUrl(svalue + "url");
    link1->SetDescription(svalue + "description");
    link1->GetUrl();
    link1->GetDescription();
    data1.AddRecord(link1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataFileFuzz(const uint8_t *data, size_t size)
{
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto file1 = std::make_shared<File>();
    file1->SetUri(svalue + "uri");
    file1->SetRemoteUri(svalue + "remoteUri");
    file1->GetUri();
    file1->GetRemoteUri();
    file1->GetSize();
    data1.AddRecord(file1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataImageFuzz(const uint8_t *data, size_t size)
{
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto image1 = std::make_shared<Image>();
    image1->SetUri(svalue + "uri");
    image1->SetRemoteUri(svalue + "remoteUri");
    data1.AddRecord(image1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataVideoFuzz(const uint8_t *data, size_t size)
{
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto video1 = std::make_shared<Video>();
    video1->SetUri(svalue + "uri");
    video1->SetRemoteUri(svalue + "remoteUri");
    data1.AddRecord(video1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataSystemDefinedRecordFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto systemDefinedRecord1 = std::make_shared<SystemDefinedRecord>();
    UDDetails details1;
    details1.insert({skey, svalue});
    systemDefinedRecord1->SetDetails(details1);
    data1.AddRecord(systemDefinedRecord1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataSystemDefinedFormFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto systemDefinedForm1 = std::make_shared<SystemDefinedForm>();
    UDDetails details1;
    details1.insert({skey, svalue});
    systemDefinedForm1->SetDetails(details1);
    auto formId = 123;
    systemDefinedForm1->SetFormId(formId);
    systemDefinedForm1->SetFormName(svalue + "formName");
    systemDefinedForm1->SetModule(svalue + "module");
    systemDefinedForm1->SetAbilityName(svalue + "abilityName");
    systemDefinedForm1->SetBundleName(svalue + "bundleName");
    systemDefinedForm1->GetFormId();
    systemDefinedForm1->GetFormName();
    systemDefinedForm1->GetBundleName();
    systemDefinedForm1->GetAbilityName();
    systemDefinedForm1->GetModule();
    data1.AddRecord(systemDefinedForm1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataSystemDefinedAppItemFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto systemDefinedAppItem1 = std::make_shared<SystemDefinedAppItem>();
    UDDetails details1;
    details1.insert({skey, svalue});
    systemDefinedAppItem1->SetDetails(details1);
    systemDefinedAppItem1->SetAppId(svalue + "appId");
    systemDefinedAppItem1->SetAppName(svalue + "appName");
    systemDefinedAppItem1->SetAppIconId(svalue + "appIconId");
    systemDefinedAppItem1->SetAppLabelId(svalue + "appLabelId");
    systemDefinedAppItem1->SetBundleName(svalue + "bundleName");
    systemDefinedAppItem1->SetAbilityName(svalue + "abilityName");
    systemDefinedAppItem1->GetAppId();
    systemDefinedAppItem1->GetAppName();
    systemDefinedAppItem1->GetBundleName();
    systemDefinedAppItem1->GetAbilityName();
    systemDefinedAppItem1->GetAppIconId();
    systemDefinedAppItem1->GetAppLabelId();
    data1.AddRecord(systemDefinedAppItem1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void SetDataSystemDefinedPixelMapFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData data1;
    std::string key;
    auto systemDefinedPixelMap1 = std::make_shared<SystemDefinedPixelMap>();
    UDDetails details1;
    details1.insert({skey, svalue});
    systemDefinedPixelMap1->SetDetails(details1);
    std::vector<uint8_t> rawData1 = {1, 2, 3, 4, 5};
    systemDefinedPixelMap1->SetRawData(rawData1);
    data1.AddRecord(systemDefinedPixelMap1);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetNativeToken();

    QueryOption option2 = {.key = key};
    Privilege privilege;
    privilege.readPermission = "readPermission";
    privilege.writePermission = "writePermission";
    UdmfClient::GetInstance().AddPrivilege(option2, privilege);

    SetHapToken();

    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void GetSummaryFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    CustomOption option1 = {.intention = Intention::UD_INTENTION_DRAG};
    UnifiedData UData;
    std::string key;

    UDDetails details;
    details.insert({skey, svalue});

    auto text = std::make_shared<Text>();
    text->SetDetails(details);
    UData.AddRecord(text);

    auto plainText = std::make_shared<PlainText>();
    plainText->SetDetails(details);
    plainText->SetContent(svalue + "content");
    plainText->SetAbstract(svalue + "abstract");
    UData.AddRecord(plainText);

    auto file = std::make_shared<File>();
    file->SetUri(svalue + "uri");
    file->SetRemoteUri(svalue + "remoteUri");
    UData.AddRecord(file);

    auto image = std::make_shared<Image>();
    image->SetUri(svalue + "uri");
    image->SetRemoteUri(svalue + "remoteUri");
    UData.AddRecord(image);

    auto systemDefinedRecord = std::make_shared<SystemDefinedRecord>();
    systemDefinedRecord->SetDetails(details);
    UData.AddRecord(systemDefinedRecord);

    auto systemDefinedForm = std::make_shared<SystemDefinedForm>();
    systemDefinedForm->SetDetails(details);
    auto formId = 123;
    systemDefinedForm->SetFormId(formId);
    systemDefinedForm->SetFormName(svalue + "formName");
    systemDefinedForm->SetModule(svalue + "module");
    systemDefinedForm->SetAbilityName(svalue + "abilityName");
    systemDefinedForm->SetBundleName(svalue + "bundleName");
    UData.AddRecord(systemDefinedForm);

    UdmfClient::GetInstance().SetData(option1, UData, key);

    QueryOption option2 = {.key = key};
    Summary summary;
    UdmfClient::GetInstance().GetSummary(option2, summary);
    UnifiedData data2;
    UdmfClient::GetInstance().GetData(option2, data2);
}

void GetBatchDataByKeyFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetHapToken();
    QueryOption option2 = { .key = key };
    std::vector<UnifiedData> dataSet2;
    UdmfClient::GetInstance().GetBatchData(option2, dataSet2);

    SetHapToken();
    QueryOption option3 = { .key = skey };
    std::vector<UnifiedData> dataSet3;
    UdmfClient::GetInstance().GetBatchData(option3, dataSet3);
}

void GetBatchDataByIntentionFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetHapToken();
    Intention intention = UnifiedDataUtils::GetIntentionByString(skey);
    QueryOption option2 = { .intention = intention };
    std::vector<UnifiedData> dataSet;
    UdmfClient::GetInstance().GetBatchData(option2, dataSet);
}

void DeleteDataByKeyFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetHapToken();
    QueryOption option2 = { .key = key };
    std::vector<UnifiedData> dataSet2;
    UdmfClient::GetInstance().DeleteData(option2, dataSet2);

    SetHapToken();
    QueryOption option3 = { .key = skey };
    std::vector<UnifiedData> dataSet3;
    UdmfClient::GetInstance().DeleteData(option3, dataSet3);
}

void DeleteDataByIntentionFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetHapToken();
    Intention intention = UnifiedDataUtils::GetIntentionByString(skey);
    QueryOption option2 = { .intention = intention };
    std::vector<UnifiedData> dataSet;
    UdmfClient::GetInstance().DeleteData(option2, dataSet);
}

void UpdateDataFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    SetHapToken();
    UnifiedData data2;
    data2.AddRecord(plainText);
    QueryOption option2 = { .key = key };
    UdmfClient::GetInstance().UpdateData(option2, data2);

    SetHapToken();
    UnifiedData data3;
    data3.AddRecord(plainText);
    QueryOption option3 = { .key = skey };
    UdmfClient::GetInstance().UpdateData(option3, data3);
}

void StartAsyncDataRetrievalFuzz(const uint8_t *data, size_t size)
{
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    std::string content(data, data + size);
    plainText->SetContent(content);
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    QueryOption query = {.key = key, .intention = UDMF::UD_INTENTION_DRAG};
    GetDataParams params = {.query = query};
    params.progressIndicator = ProgressIndicator::DEFAULT;
    params.progressListener = [](ProgressInfo progressInfo, std::shared_ptr<UnifiedData> data) {};
    UdmfAsyncClient::GetInstance().StartAsyncDataRetrieval(params);
}

void CancelAsyncDataRetrievalFuzz(const uint8_t *data, size_t size)
{
    CustomOption option1 = { .intention = UD_INTENTION_DATA_HUB };
    UnifiedData data1;
    std::string key;
    auto plainText = std::make_shared<PlainText>();
    std::string content(data, data + size);
    plainText->SetContent(content);
    data1.AddRecord(plainText);
    UdmfClient::GetInstance().SetData(option1, data1, key);

    QueryOption query = {.key = key, .intention = UDMF::UD_INTENTION_DRAG};
    GetDataParams params = {.query = query};
    params.progressIndicator = ProgressIndicator::NONE;
    params.progressListener = [](ProgressInfo progressInfo, std::shared_ptr<UnifiedData> data) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    };
    UdmfAsyncClient::GetInstance().StartAsyncDataRetrieval(params);
    UdmfAsyncClient::GetInstance().Cancel(key);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SetUpTestCase();
    OHOS::SetDataFileFuzz(data, size);
    OHOS::SetDataHtmlFuzz(data, size);
    OHOS::SetDataImageFuzz(data, size);
    OHOS::SetDataLinkFuzz(data, size);
    OHOS::SetDataPlainTextFuzz(data, size);
    OHOS::SetDataSystemDefinedAppItemFuzz(data, size);
    OHOS::SetDataSystemDefinedFormFuzz(data, size);
    OHOS::SetDataSystemDefinedPixelMapFuzz(data, size);
    OHOS::SetDataSystemDefinedRecordFuzz(data, size);
    OHOS::SetDataTextFuzz(data, size);
    OHOS::SetDataVideoFuzz(data, size);
    OHOS::GetSummaryFuzz(data, size);
    OHOS::GetBatchDataByKeyFuzz(data, size);
    OHOS::GetBatchDataByIntentionFuzz(data, size);
    OHOS::DeleteDataByKeyFuzz(data, size);
    OHOS::DeleteDataByIntentionFuzz(data, size);
    OHOS::UpdateDataFuzz(data, size);
    OHOS::StartAsyncDataRetrievalFuzz(data, size);
    OHOS::CancelAsyncDataRetrievalFuzz(data, size);
    OHOS::TearDown();
    return 0;
}
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
#define LOG_TAG "UnifiedKey"
#include <sstream>
#include "unified_key.h"

#include "logger.h"

namespace OHOS {
namespace UDMF {
static std::bitset<MAX_BIT_SIZE> g_ruleIntention;
static std::bitset<MAX_BIT_SIZE> g_ruleBundleName;
static std::bitset<MAX_BIT_SIZE> g_ruleGroupId;
static constexpr const char *UNIFIED_KEY_SCHEMA = "udmf://";
static constexpr const char *ALPHA_AGGREGATE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static constexpr const char *DIGIT_AGGREGATE = "0123456789";
static constexpr const char *SYMBOL_AGGREGATE = ":;<=>?@[\\]_`";
static constexpr const char SEPARATOR = '/';
static constexpr uint32_t PREFIX_LEN = 24;
static constexpr uint32_t SUFIX_LEN = 8;
static constexpr uint32_t INDEX_LEN = 32;
UnifiedKey::UnifiedKey(std::string key)
{
    this->key = std::move(key);
}

UnifiedKey::UnifiedKey(std::string intention, std::string bundle, std::string groupId)
{
    this->intention = std::move(intention);
    this->bundleName = std::move(bundle);
    this->groupId = std::move(groupId);
}

std::string UnifiedKey::GetUnifiedKey()
{
    if (!this->key.empty()) {
        return this->key;
    }
    if (this->intention.empty() || this->groupId.empty()) {
        return "";
    }
    // Uri-compliant structure, example: udmf://drag/com.ohos.test/012345679abc
    std::ostringstream oss;
    oss << UNIFIED_KEY_SCHEMA << this->intention << SEPARATOR <<
        this->bundleName << SEPARATOR << this->groupId;
    this->key = oss.str();
    return this->key;
}

std::string UnifiedKey::GetKeyCommonPrefix() const
{
    if (this->key.size() > INDEX_LEN) {
        return this->key.substr(0, key.size() - SUFIX_LEN);
    }
    if (this->intention.empty() || this->groupId.size() < INDEX_LEN) {
        LOG_ERROR(UDMF_FRAMEWORK, "Empty property key.intention:%{public}s, groupId:%{public}s",
            intention.c_str(), groupId.c_str());
        return "";
    }
    std::ostringstream oss;
    oss << UNIFIED_KEY_SCHEMA << this->intention << SEPARATOR <<
        this->bundleName << SEPARATOR << this->groupId.substr(0, PREFIX_LEN);
    return oss.str();
}

bool UnifiedKey::IsValid()
{
    if (this->key.empty()) {
        LOG_DEBUG(UDMF_FRAMEWORK, "empty key");
        return false;
    }
    PreliminaryWork();

    std::string data = this->key; // schema/intention/groupId
    std::string separator = "://";
    size_t pos = data.find(separator);
    if (pos == std::string::npos) {
        return false;
    }
    std::string schema = data.substr(0, pos + separator.size()); // schema
    if (UNIFIED_KEY_SCHEMA != schema) {
        LOG_DEBUG(UDMF_FRAMEWORK, "wrong schema");
        return false;
    }

    data = data.substr(pos + separator.size()); // intention/bundleName/groupId
    pos = data.find('/');        // intention
    if (pos == std::string::npos) {
        return false;
    }
    std::string intentionTmp = data.substr(0, pos);
    if (!CheckCharacter(intentionTmp, g_ruleIntention)) {
        return false;
    }
    this->intention = intentionTmp;

    data = data.substr(pos + 1);
    pos = data.find('/'); // bundleName
    if (pos == std::string::npos) {
        return false;
    }
    std::string bundle = data.substr(0, pos);
    if (!CheckCharacter(bundle, g_ruleBundleName)) {
        LOG_DEBUG(UDMF_FRAMEWORK, "wrong bundle");
        return false;
    }
    this->bundleName = bundle;

    data = data.substr(pos + 1); // groupId
    if (data.empty()) {
        return false;
    }
    if (!CheckCharacter(data, g_ruleGroupId)) {
        LOG_DEBUG(UDMF_FRAMEWORK, "wrong groupId");
        return false;
    }
    this->groupId = data;
    return true;
}

bool UnifiedKey::CheckCharacter(std::string data, std::bitset<MAX_BIT_SIZE> rule)
{
    if (data.empty()) {
        LOG_DEBUG(UDMF_FRAMEWORK, "empty key");
        return false;
    }
    size_t dataLen = data.size();
    for (size_t i = 0; i < dataLen; ++i) {
        if (static_cast<int>(data[i]) >= 0 && static_cast<int>(data[i]) < 128) { // 128:ASCII Max Number
            bool isLegal = rule.test(data[i]);
            if (!isLegal) {
                return false;
            }
        }
    }
    return true;
}

void UnifiedKey::PreliminaryWork()
{
    // All intentions are composed of uppercase and lowercase letters and underscores.
    if (g_ruleIntention.none()) {
        std::string intentionTmp = std::string(ALPHA_AGGREGATE) + "_";
        for (char i : intentionTmp) {
            g_ruleIntention.set(i);
        }
    }
    // All bundle name are composed of uppercase and lowercase letters and dots.
    if (g_ruleBundleName.none()) {
        std::string bundleAggregate = std::string(ALPHA_AGGREGATE) + DIGIT_AGGREGATE + "._";
        for (char i : bundleAggregate) {
            g_ruleBundleName.set(i);
        }
    }
    // Characters of groupId are taken from Ascii codes 48 to 122.
    if (g_ruleGroupId.none()) {
        std::string idAggregate = std::string(DIGIT_AGGREGATE) + ALPHA_AGGREGATE + SYMBOL_AGGREGATE;
        for (char i : idAggregate) {
            g_ruleGroupId.set(i);
        }
    }
}
} // namespace UDMF
} // namespace OHOS
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

#ifndef UDMF_UTD_GRAPH_H
#define UDMF_UTD_GRAPH_H

#include <vector>
#include <map>
#include <stack>
#include <string>
#include <shared_mutex>
#include "graph.h"
#include "utd_common.h"
#include "preset_type_descriptors.h"

namespace OHOS {
namespace UDMF {
class UtdGraph {
public:
    static UtdGraph &GetInstance();
    bool IsValidType(const std::string &node);
    void InitUtdGraph(const std::vector<TypeDescriptorCfg> &descriptorCfgs);
    bool IsLowerLevelType(const std::string &lowerLevelType, const std::string &heigitLevelType);
    std::unique_ptr<Graph> ConstructNewGraph(const std::vector<TypeDescriptorCfg> &descriptorCfgs);
    void Update(std::unique_ptr<Graph> graph);
private:
    UtdGraph();
    ~UtdGraph();
    UtdGraph(const UtdGraph &obj) = delete;
    UtdGraph &operator=(const UtdGraph &obj) = delete;
    std::mutex graphMutex_;
    std::unique_ptr<Graph> graph_;
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_UTD_GRAPH_H

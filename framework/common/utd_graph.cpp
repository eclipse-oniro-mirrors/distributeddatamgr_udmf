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

#include "utd_graph.h"
#include "logger.h"
namespace OHOS {
namespace UDMF {
UtdGraph::UtdGraph()
{
    LOG_INFO(UDMF_CLIENT, "construct UtdGraph sucess.");
}

UtdGraph::~UtdGraph()
{
}

UtdGraph &UtdGraph::GetInstance()
{
    static auto instance = new UtdGraph();
    return *instance;
}

bool UtdGraph::IsValidType(const std::string &node)
{
    if (typeIdIndex_.find(node) == typeIdIndex_.end()) {
        LOG_ERROR(UDMF_CLIENT, "invalid typeId. typeId:%{public}s ", node.c_str());
        return false;
    }
    return true;
}

uint32_t UtdGraph::GetIndex(const std::string &node)
{
    return typeIdIndex_.at(node);
}

void UtdGraph::InitUtdGraph(std::vector<TypeDescriptorCfg> descriptorCfgs)
{
    uint32_t descriptorsNum = static_cast<uint32_t>(descriptorCfgs.size());
    std::unique_lock<std::shared_mutex> Lock(graphMutex_);
    graph_ = new Graph(descriptorsNum);
    for (uint32_t i = 0; i < descriptorsNum; i++) {
        typeIdIndex_.insert(std::make_pair(descriptorCfgs[i].typeId, i));
    }
    for (auto &descriptorCfg : descriptorCfgs) {
        std::set<std::string> belongsTo = descriptorCfg.belongingToTypes;
        for (auto belongsToType : belongsTo) {
            AddEdge(belongsToType, descriptorCfg.typeId);
        }
    }
}

void UtdGraph::AddEdge(const std::string &startNode, const std::string &endNode)
{
    uint32_t start = GetIndex(startNode);
    uint32_t end = GetIndex(endNode);
    graph_->AddEdge(start, end);
}

bool UtdGraph::IsLowerLevelType(const std::string &lowerLevelType, const std::string &heigitLevelType)
{
    bool isFind = false;
    uint32_t start = GetIndex(lowerLevelType);
    uint32_t end = GetIndex(heigitLevelType);
    std::shared_lock<decltype(graphMutex_)> Lock(graphMutex_);
    graph_->Dfs(start, true, [&isFind, &end](uint32_t currNode)-> bool {
        if (end == currNode) {
            isFind = true;
            return true;
        }
        return false;
    });
    return isFind;
}
} // namespace UDMF
} // namespace OHOS
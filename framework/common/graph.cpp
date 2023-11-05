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
#include "graph.h"
#include "securec.h"
using namespace std;
namespace OHOS {
namespace UDMF {
void Graph::CreateAdjList(uint32_t vesNum, vector<vector<uint32_t>> edges)
{
    vesNum_ = vesNum;
    for (uint32_t node = 0; node < vesNum_; node++) {
        adjList_[node].value = node;
        adjList_[node].firstEdge = nullptr;
    }
    uint32_t start;
    uint32_t end;
    EdgeNode *edge;
    for (auto edgeNode : edges) {
        start = edgeNode[0];
        end = edgeNode[1];
        edge = new EdgeNode;   // add new edge
        edge->adjIndex = end;
        edge->next = adjList_[start].firstEdge;
        adjList_[start].firstEdge = edge;
    }
}

void Graph::Dfs(uint32_t startNode, bool isInit, Action action)
{
    if (isInit) {
        (void)memset_s(visited_, sizeof(visited_), 0, sizeof(visited_));
    }
    stack <uint32_t>nodes;
    EdgeNode *edge = nullptr;
    visited_[startNode] = 1;
    nodes.push(startNode);
    if (action(adjList_[startNode].value)) {
        return;
    }
    while (!nodes.empty()) {
        edge = adjList_[nodes.top()].firstEdge;
        while (edge) {
            if (visited_[edge->adjIndex] == 0) {
                visited_[edge->adjIndex] = 1;
                if (action(adjList_[edge->adjIndex].value)) {
                    return;
                }
                nodes.push(edge->adjIndex);
                edge = adjList_[edge->adjIndex].firstEdge;
            } else {
                edge = edge->next;
            }
        }
        if (edge == nullptr) {
            nodes.pop();
        }
    }
}

vector<uint32_t> Graph::DfsUnconnectedGraph()
{
    (void)memset_s(visited_, sizeof(visited_), 0, sizeof(visited_));
    vector<uint32_t> result;
    for (uint32_t node = 0; node < vesNum_; node++) {
        if (!visited_[node]) {
            Dfs(node, false, [&](uint32_t currNode) -> bool {
                result.push_back(currNode);
                return false;
            });
        }
    }
    return result;
}
} // namespace UDMF
} // namespace OHOS
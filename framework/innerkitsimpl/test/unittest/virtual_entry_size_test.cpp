/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <limits>
#include <utility>

#include "gtest/gtest.h"
#include "virtual_entry.h"

using namespace testing::ext;

namespace OHOS::UDMF {
class VirtualEntrySizeTest : public testing::Test {
};

/**
 * @tc.name: HasValidFileSizes_FileBoundaries_RequireNonNegativeSize
 * @tc.desc: Verify unset and negative sizes fail while a real empty file and maximum size remain valid.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntrySizeTest, HasValidFileSizes_FileBoundaries_RequireNonNegativeSize, TestSize.Level0)
{
    VirtualEntry file;
    EXPECT_FALSE(file.HasValidFileSizes());
    for (int64_t size : { int64_t(-1), int64_t(-2), std::numeric_limits<int64_t>::min() }) {
        file.size = size;
        EXPECT_FALSE(file.HasValidFileSizes());
    }
    file.size = 0;
    EXPECT_TRUE(file.HasValidFileSizes());
    file.size = std::numeric_limits<int64_t>::max();
    EXPECT_TRUE(file.HasValidFileSizes());
}

/**
 * @tc.name: HasValidFileSizes_DirectoryWithoutSize_AcceptEmptyDirectory
 * @tc.desc: Verify only file items require a declared size.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntrySizeTest, HasValidFileSizes_DirectoryWithoutSize_AcceptEmptyDirectory, TestSize.Level0)
{
    VirtualEntry directory;
    directory.type = VirtualEntryType::DIRECTORY;
    EXPECT_EQ(directory.size, -1);
    EXPECT_TRUE(directory.HasValidFileSizes());
}

/**
 * @tc.name: HasValidFileSizes_NestedMissingSize_RejectEntireTree
 * @tc.desc: Verify the client checks every file before attaching or registering a virtual tree.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntrySizeTest, HasValidFileSizes_NestedMissingSize_RejectEntireTree, TestSize.Level0)
{
    VirtualEntry root;
    root.type = VirtualEntryType::DIRECTORY;
    VirtualEntry sized;
    sized.size = 7;
    root.subItems.push_back(sized);
    VirtualEntry nested;
    nested.type = VirtualEntryType::DIRECTORY;
    nested.subItems.emplace_back();
    root.subItems.push_back(nested);
    EXPECT_FALSE(root.HasValidFileSizes());
    root.subItems.back().subItems.front().size = 0;
    EXPECT_TRUE(root.HasValidFileSizes());
}

/**
 * @tc.name: HasValidFileSizes_MaximumDepth_RejectDeeperTree
 * @tc.desc: Verify size validation is bounded at the existing 64-level tree limit.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntrySizeTest, HasValidFileSizes_MaximumDepth_RejectDeeperTree, TestSize.Level0)
{
    VirtualEntry tree;
    tree.size = 1;
    for (size_t depth = 0; depth < 64; ++depth) {
        VirtualEntry parent;
        parent.type = VirtualEntryType::DIRECTORY;
        parent.subItems.push_back(std::move(tree));
        tree = std::move(parent);
    }
    EXPECT_TRUE(tree.HasValidFileSizes());
    VirtualEntry overflow;
    overflow.type = VirtualEntryType::DIRECTORY;
    overflow.subItems.push_back(std::move(tree));
    EXPECT_FALSE(overflow.HasValidFileSizes());
}

/**
 * @tc.name: HasValidFileSizes_InvalidKind_RejectInvalidDescendant
 * @tc.desc: Verify an invalid item discriminator cannot bypass required size validation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntrySizeTest, HasValidFileSizes_InvalidKind_RejectInvalidDescendant, TestSize.Level0)
{
    VirtualEntry invalid;
    invalid.type = static_cast<VirtualEntryType>(99);
    invalid.size = 0;
    EXPECT_FALSE(invalid.HasValidFileSizes());
    VirtualEntry directory;
    directory.type = VirtualEntryType::DIRECTORY;
    directory.subItems.push_back(invalid);
    EXPECT_FALSE(directory.HasValidFileSizes());
}
} // namespace OHOS::UDMF

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

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "file.h"
#include "udmf_client.h"
#include "udmf_err_code.h"
#include "virtual_entry_attachment_registry.h"
#include "virtual_entry_capi.h"

using namespace testing::ext;

namespace OHOS::UDMF {
namespace {
using ItemPtr = std::unique_ptr<OH_UdmfVirtualItem, decltype(&OH_UdmfVirtualItem_Destroy)>;
using InfoPtr = std::unique_ptr<OH_UdmfVirtualFileInfo, decltype(&OH_UdmfVirtualFileInfo_Destroy)>;
using UriPtr = std::unique_ptr<OH_UdsFileUri, decltype(&OH_UdsFileUri_Destroy)>;

struct CallbackContext {
    int readStatus = UDMF_E_OK;
    int cancelStatus = UDMF_E_OK;
    int statMode = 0;
    bool oversize = false;
    bool holdReads = false;
    bool releaseReads = false;
    size_t readCalls = 0;
    size_t cancelCalls = 0;
    size_t finalized = 0;
    int64_t lastOffset = -1;
    uint32_t lastLength = 0;
    std::vector<std::string> canceledIds;
    std::vector<uint8_t> content{ 0, 1, 2, 3, 4, 5, 6 };
    std::mutex mutex;
    std::condition_variable condition;
};

OH_UdmfVirtualItem *OnStat(void *value, const char *id)
{
    auto &context = *static_cast<CallbackContext *>(value);
    if (context.statMode == 1) {
        return nullptr;
    }
    if (context.statMode == 2) {
        return OH_UdmfVirtualItem_CreateDirectory("directory", 123);
    }
    auto item = OH_UdmfVirtualItem_CreateFile("example.bin", id, 123);
    if (item != nullptr && context.statMode != 3) {
        (void)OH_UdmfVirtualItem_SetFileSize(item, static_cast<int64_t>(context.content.size()));
    }
    return item;
}

int OnRead(void *value, const char *id, int64_t offset, uint32_t length, uint8_t *data, uint32_t *bytesRead)
{
    (void)id;
    auto &context = *static_cast<CallbackContext *>(value);
    std::unique_lock<std::mutex> lock(context.mutex);
    ++context.readCalls;
    context.lastOffset = offset;
    context.lastLength = length;
    context.condition.notify_all();
    if (context.holdReads) {
        context.condition.wait(lock, [&context] { return context.releaseReads; });
    }
    if (context.readStatus != UDMF_E_OK) {
        return context.readStatus;
    }
    size_t available = static_cast<size_t>(offset) >= context.content.size()
        ? 0 : context.content.size() - static_cast<size_t>(offset);
    auto count = static_cast<uint32_t>(std::min<size_t>(length, available));
    if (count != 0) {
        std::copy_n(context.content.data() + offset, count, data);
    }
    *bytesRead = context.oversize ? length + 1 : count;
    return UDMF_E_OK;
}

int OnCancel(void *value, const char* const *ids, uint32_t count)
{
    auto &context = *static_cast<CallbackContext *>(value);
    ++context.cancelCalls;
    context.canceledIds.assign(ids, ids + count);
    return context.cancelStatus;
}

void OnFinalize(void *value)
{
    ++static_cast<CallbackContext *>(value)->finalized;
}

OH_UdmfVirtualFileCallbacks MakeCallbacks()
{
    OH_UdmfVirtualFileCallbacks callbacks{};
    callbacks.structSize = sizeof(callbacks);
    callbacks.onStat = OnStat;
    callbacks.onRead = OnRead;
    callbacks.onCancel = OnCancel;
    return callbacks;
}

struct AttachmentOwner {
    ~AttachmentOwner()
    {
        VirtualEntryAttachmentRegistry::Detach(this);
    }
};
} // namespace

class VirtualEntryCapiTest : public testing::Test {
public:
    void SetUp() override
    {
        callbacks_ = MakeCallbacks();
        item_.reset(OH_UdmfVirtualItem_CreateFile("example.bin", "file-id", 123));
        if (OH_UdmfVirtualItem_SetFileSize(item_.get(), 7) == UDMF_E_OK) {
            info_.reset(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks_, &context_, OnFinalize));
        }
        if (info_ != nullptr) {
            provider_ = CreateNdkVirtualEntryProvider(info_->info_);
        }
    }

protected:
    CallbackContext context_;
    OH_UdmfVirtualFileCallbacks callbacks_{};
    ItemPtr item_{ nullptr, OH_UdmfVirtualItem_Destroy };
    InfoPtr info_{ nullptr, OH_UdmfVirtualFileInfo_Destroy };
    sptr<IVirtualEntryProvider> provider_;
};

/**
 * @tc.name: CreateFile_InvalidNamesAndIds_RejectInput
 * @tc.desc: Verify null, empty, path-like and oversized names and IDs cannot create virtual files.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, CreateFile_InvalidNamesAndIds_RejectInput, TestSize.Level0)
{
    EXPECT_EQ(OH_UdmfVirtualItem_CreateFile(nullptr, "id", 0), nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_CreateFile("file", nullptr, 0), nullptr);
    for (const char *name : { "", ".", "..", "a/b", "a\\b" }) {
        SCOPED_TRACE(name);
        EXPECT_EQ(OH_UdmfVirtualItem_CreateFile(name, "id", 0), nullptr);
        EXPECT_EQ(OH_UdmfVirtualItem_CreateDirectory(name, 0), nullptr);
    }
    EXPECT_EQ(OH_UdmfVirtualItem_CreateDirectory(nullptr, 0), nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_CreateFile(std::string(256, 'a').c_str(), "id", 0), nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_CreateDirectory(std::string(256, 'a').c_str(), 0), nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_CreateFile("file", "", 0), nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_CreateFile("file", std::string(1025, 'i').c_str(), 0), nullptr);
}

/**
 * @tc.name: CreateFile_MaximumLengths_AcceptBoundary
 * @tc.desc: Verify maximum valid name and ID lengths are not rejected by off-by-one checks.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, CreateFile_MaximumLengths_AcceptBoundary, TestSize.Level0)
{
    ItemPtr file(OH_UdmfVirtualItem_CreateFile(std::string(255, 'a').c_str(),
        std::string(1024, 'i').c_str(), std::numeric_limits<int64_t>::max()), OH_UdmfVirtualItem_Destroy);
    ItemPtr directory(OH_UdmfVirtualItem_CreateDirectory(std::string(255, 'd').c_str(), 0),
        OH_UdmfVirtualItem_Destroy);
    ASSERT_NE(file, nullptr);
    EXPECT_EQ(file->entry_.id.size(), 1024u);
    EXPECT_EQ(file->entry_.name.size(), 255u);
    EXPECT_NE(directory, nullptr);
}

/**
 * @tc.name: Mutators_NullOrWrongKind_RejectSafely
 * @tc.desc: Verify null handles, self-insertion and file-as-parent calls are rejected.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Mutators_NullOrWrongKind_RejectSafely, TestSize.Level0)
{
    ASSERT_NE(item_, nullptr);
    ItemPtr directory(OH_UdmfVirtualItem_CreateDirectory("dir", 0), OH_UdmfVirtualItem_Destroy);
    ASSERT_NE(directory, nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_SetFileSize(nullptr, 0), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_ClearFileSize(nullptr), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(nullptr, item_.get()), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(directory.get(), nullptr), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(directory.get(), directory.get()), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(item_.get(), directory.get()), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_SetFileSize(directory.get(), 0), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_ClearFileSize(directory.get()), UDMF_E_INVALID_PARAM);
    OH_UdmfVirtualItem_Destroy(nullptr);
    EXPECT_TRUE(directory->entry_.subItems.empty());
}

/**
 * @tc.name: SetAndClearFileSize_Boundaries_PreserveMetadata
 * @tc.desc: Verify valid size extremes and clearing size do not corrupt other metadata.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, SetAndClearFileSize_Boundaries_PreserveMetadata, TestSize.Level0)
{
    ASSERT_NE(item_, nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), -1), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), 0), UDMF_E_OK);
    EXPECT_EQ(item_->entry_.size, 0);
    EXPECT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), std::numeric_limits<int64_t>::max()), UDMF_E_OK);
    EXPECT_EQ(item_->entry_.size, std::numeric_limits<int64_t>::max());
    EXPECT_EQ(OH_UdmfVirtualItem_ClearFileSize(item_.get()), UDMF_E_OK);
    EXPECT_EQ(item_->entry_.size, -1);
    EXPECT_EQ(item_->entry_.name, "example.bin");
    EXPECT_EQ(item_->entry_.modifyTime, 123);
}

/**
 * @tc.name: AddChild_DeepCopy_KeepSnapshotAfterSourceChanges
 * @tc.desc: Verify a directory retains an independent child snapshot after the original changes or is destroyed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, AddChild_DeepCopy_KeepSnapshotAfterSourceChanges, TestSize.Level0)
{
    ItemPtr directory(OH_UdmfVirtualItem_CreateDirectory("dir", 0), OH_UdmfVirtualItem_Destroy);
    ASSERT_NE(directory, nullptr);
    ASSERT_NE(item_, nullptr);
    ASSERT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), 7), UDMF_E_OK);
    ASSERT_EQ(OH_UdmfVirtualItem_AddChild(directory.get(), item_.get()), UDMF_E_OK);
    ASSERT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), 99), UDMF_E_OK);
    item_.reset();
    ASSERT_EQ(directory->entry_.subItems.size(), 1u);
    EXPECT_EQ(directory->entry_.subItems.front().size, 7);
    EXPECT_EQ(directory->entry_.subItems.front().id, "file-id");
}

/**
 * @tc.name: AddChild_MaximumDepth_RejectWithoutPartialMutation
 * @tc.desc: Verify depth 64 is accepted and a deeper candidate leaves its parent unchanged.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, AddChild_MaximumDepth_RejectWithoutPartialMutation, TestSize.Level0)
{
    ItemPtr tree(OH_UdmfVirtualItem_CreateFile("leaf", "id", 0), OH_UdmfVirtualItem_Destroy);
    ASSERT_EQ(OH_UdmfVirtualItem_SetFileSize(tree.get(), 0), UDMF_E_OK);
    ASSERT_NE(tree, nullptr);
    for (size_t depth = 0; depth < 64; ++depth) {
        ItemPtr parent(OH_UdmfVirtualItem_CreateDirectory("dir", 0), OH_UdmfVirtualItem_Destroy);
        ASSERT_NE(parent, nullptr);
        ASSERT_EQ(OH_UdmfVirtualItem_AddChild(parent.get(), tree.get()), UDMF_E_OK);
        tree = std::move(parent);
    }
    ItemPtr overflow(OH_UdmfVirtualItem_CreateDirectory("overflow", 0), OH_UdmfVirtualItem_Destroy);
    ASSERT_NE(overflow, nullptr);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(overflow.get(), tree.get()), UDMF_E_INVALID_PARAM);
    EXPECT_TRUE(overflow->entry_.subItems.empty());
}

/**
 * @tc.name: AddChild_NodeQuota_IncludeRootInLimit
 * @tc.desc: Verify the root counts toward the 4096-node quota and failed insertion is atomic.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, AddChild_NodeQuota_IncludeRootInLimit, TestSize.Level1)
{
    ItemPtr directory(OH_UdmfVirtualItem_CreateDirectory("dir", 0), OH_UdmfVirtualItem_Destroy);
    ASSERT_NE(directory, nullptr);
    // Prepare a valid boundary tree without quadratic copying through 4095 insertions.
    for (size_t index = 0; index < 4094; ++index) {
        VirtualEntry child;
        child.name = "file-" + std::to_string(index);
        child.id = child.name;
        child.size = 0;
        directory->entry_.subItems.push_back(std::move(child));
    }
    ASSERT_EQ(OH_UdmfVirtualItem_AddChild(directory.get(), item_.get()), UDMF_E_OK);
    EXPECT_EQ(directory->entry_.subItems.size(), 4095u);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(directory.get(), item_.get()), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(directory->entry_.subItems.size(), 4095u);
}

/**
 * @tc.name: CreateInfo_InvalidCallbacks_DoNotAcquireContext
 * @tc.desc: Verify invalid callback tables and unmanaged contexts do not transfer ownership.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, CreateInfo_InvalidCallbacks_DoNotAcquireContext, TestSize.Level0)
{
    ASSERT_NE(item_, nullptr);
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(nullptr, &callbacks_, &context_, OnFinalize), nullptr);
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), nullptr, &context_, OnFinalize), nullptr);
    auto callbacks = callbacks_;
    callbacks.structSize = sizeof(callbacks) - 1;
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks, &context_, OnFinalize), nullptr);
    callbacks = callbacks_;
    callbacks.onRead = nullptr;
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks, &context_, OnFinalize), nullptr);
    callbacks = callbacks_;
    callbacks.onCancel = nullptr;
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks, &context_, OnFinalize), nullptr);
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks_, &context_, nullptr), nullptr);
    EXPECT_EQ(context_.finalized, 0u);
}

/**
 * @tc.name: CreateInfo_MissingSize_RejectEvenWithStat
 * @tc.desc: Verify every file requires a size even when a stat callback is supplied.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, CreateInfo_MissingSize_RejectEvenWithStat, TestSize.Level0)
{
    ASSERT_NE(item_, nullptr);
    ASSERT_EQ(OH_UdmfVirtualItem_ClearFileSize(item_.get()), UDMF_E_OK);
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks_, &context_, OnFinalize), nullptr);
    auto callbacks = callbacks_;
    callbacks.onStat = nullptr;
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks, &context_, OnFinalize), nullptr);
    EXPECT_EQ(context_.finalized, 0u);
    ASSERT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), 0), UDMF_E_OK);
    InfoPtr known(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks, &context_, OnFinalize),
        OH_UdmfVirtualFileInfo_Destroy);
    EXPECT_NE(known, nullptr);
}

/**
 * @tc.name: CreateInfo_NestedMissingSize_RejectEveryDescendant
 * @tc.desc: Verify both directory insertion and virtual info creation reject an unset descendant size.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, CreateInfo_NestedMissingSize_RejectEveryDescendant, TestSize.Level0)
{
    ItemPtr directory(OH_UdmfVirtualItem_CreateDirectory("dir", 0), OH_UdmfVirtualItem_Destroy);
    ASSERT_NE(directory, nullptr);
    ASSERT_EQ(OH_UdmfVirtualItem_ClearFileSize(item_.get()), UDMF_E_OK);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(directory.get(), item_.get()), UDMF_E_INVALID_PARAM);
    EXPECT_TRUE(directory->entry_.subItems.empty());
    directory->entry_.subItems.push_back(item_->entry_);
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(directory.get(), &callbacks_, &context_, OnFinalize), nullptr);
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    EXPECT_FALSE(VirtualEntryAttachmentRegistry::Attach(file, directory->entry_, provider_->AsObject(), &owner));
}

/**
 * @tc.name: SetVirtualEntry_InvalidHandles_RejectInput
 * @tc.desc: Verify null file-URI or info handles are rejected and clearing an empty URI is idempotent.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, SetVirtualEntry_InvalidHandles_RejectInput, TestSize.Level0)
{
    UriPtr uri(OH_UdsFileUri_Create(), OH_UdsFileUri_Destroy);
    ASSERT_NE(uri, nullptr);
    ASSERT_NE(info_, nullptr);
    EXPECT_EQ(OH_UdsFileUri_SetVirtualEntry(nullptr, info_.get()), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdsFileUri_SetVirtualEntry(uri.get(), nullptr), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdsFileUri_ClearVirtualEntry(nullptr), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdsFileUri_ClearVirtualEntry(uri.get()), UDMF_E_OK);
    EXPECT_EQ(OH_UdsFileUri_ClearVirtualEntry(uri.get()), UDMF_E_OK);
    OH_UdmfVirtualFileInfo_Destroy(nullptr);
}

/**
 * @tc.name: Finalize_MultipleUris_ReleaseExactlyOnceAfterLastOwner
 * @tc.desc: Verify context ownership survives info destruction and multiple file-URI references.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Finalize_MultipleUris_ReleaseExactlyOnceAfterLastOwner, TestSize.Level0)
{
    CallbackContext context;
    InfoPtr info(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks_, &context, OnFinalize),
        OH_UdmfVirtualFileInfo_Destroy);
    UriPtr first(OH_UdsFileUri_Create(), OH_UdsFileUri_Destroy);
    UriPtr second(OH_UdsFileUri_Create(), OH_UdsFileUri_Destroy);
    ASSERT_NE(info, nullptr);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_EQ(OH_UdsFileUri_SetVirtualEntry(first.get(), info.get()), UDMF_E_OK);
    ASSERT_EQ(OH_UdsFileUri_SetVirtualEntry(second.get(), info.get()), UDMF_E_OK);
    info.reset();
    EXPECT_EQ(context.finalized, 0u);
    EXPECT_EQ(OH_UdsFileUri_ClearVirtualEntry(first.get()), UDMF_E_OK);
    EXPECT_EQ(context.finalized, 0u);
    second.reset();
    EXPECT_EQ(context.finalized, 1u);
    EXPECT_EQ(OH_UdsFileUri_ClearVirtualEntry(first.get()), UDMF_E_OK);
    EXPECT_EQ(context.finalized, 1u);
}

/**
 * @tc.name: Factory_MissingInfoOrCallbacks_RejectProvider
 * @tc.desc: Verify a provider cannot be created without retained callback state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Factory_MissingInfoOrCallbacks_RejectProvider, TestSize.Level0)
{
    EXPECT_EQ(CreateNdkVirtualEntryProvider(nullptr), nullptr);
    auto info = std::make_shared<NdkVirtualEntryInfo>();
    EXPECT_EQ(CreateNdkVirtualEntryProvider(info), nullptr);
    EXPECT_FALSE(AttachNdkVirtualEntry(nullptr, nullptr));
}

/**
 * @tc.name: Stat_InvalidIds_RejectBeforeCallback
 * @tc.desc: Verify empty, embedded-NUL and oversized file IDs are rejected.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Stat_InvalidIds_RejectBeforeCallback, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    VirtualEntry entry;
    for (const auto &id : { std::string(), std::string("a\0b", 3), std::string(1025, 'i') }) {
        EXPECT_EQ(provider_->Stat(id, entry), -EINVAL);
    }
}

/**
 * @tc.name: Stat_CallbackResults_ValidateKindAndPropagateMetadata
 * @tc.desc: Verify callbacks must return a file with an explicit non-negative size.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Stat_CallbackResults_ValidateKindAndPropagateMetadata, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    VirtualEntry entry;
    context_.statMode = 1;
    EXPECT_EQ(provider_->Stat("file-id", entry), -EIO);
    context_.statMode = 2;
    EXPECT_EQ(provider_->Stat("file-id", entry), -EINVAL);
    context_.statMode = 3;
    EXPECT_EQ(provider_->Stat("file-id", entry), -EINVAL);
    context_.statMode = 0;
    EXPECT_EQ(provider_->Stat("file-id", entry), 0);
    EXPECT_EQ(entry.id, "file-id");
    EXPECT_EQ(entry.size, 7);
    EXPECT_EQ(entry.modifyTime, 123);
}

/**
 * @tc.name: Read_InvalidRequests_DoNotCallApplication
 * @tc.desc: Verify all range and ID guards run before the application callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Read_InvalidRequests_DoNotCallApplication, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(provider_->Read("", 0, 1, bytes), -EINVAL);
    EXPECT_EQ(provider_->Read(std::string("a\0b", 3), 0, 1, bytes), -EINVAL);
    EXPECT_EQ(provider_->Read("file", -1, 1, bytes), -EINVAL);
    EXPECT_EQ(provider_->Read("file", 0, -1, bytes), -EINVAL);
    EXPECT_EQ(provider_->Read("file", 0, 5 * 1024 * 1024 + 1, bytes), -EINVAL);
    EXPECT_EQ(context_.readCalls, 0u);
}

/**
 * @tc.name: Read_ZeroLength_ClearBufferWithoutApplicationCallback
 * @tc.desc: Verify a zero-length read succeeds without consuming a callback slot.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Read_ZeroLength_ClearBufferWithoutApplicationCallback, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    std::vector<uint8_t> bytes{ 1 };
    EXPECT_EQ(provider_->Read("file", 0, 0, bytes), 0);
    EXPECT_TRUE(bytes.empty());
    EXPECT_EQ(context_.readCalls, 0u);
}

/**
 * @tc.name: Read_OffsetShortReadAndEof_PreserveByteContract
 * @tc.desc: Verify partial data, offsets and EOF preserve the requested length and byte count.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Read_OffsetShortReadAndEof_PreserveByteContract, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(provider_->Read("file", 3, 32, bytes), 0);
    EXPECT_EQ(bytes, (std::vector<uint8_t>{ 3, 4, 5, 6 }));
    EXPECT_EQ(context_.lastOffset, 3);
    EXPECT_EQ(context_.lastLength, 32u);
    EXPECT_EQ(provider_->Read("file", 7, 1, bytes), 0);
    EXPECT_TRUE(bytes.empty());
    EXPECT_EQ(provider_->Read("file", 0, 5 * 1024 * 1024, bytes), 0);
    EXPECT_EQ(bytes, context_.content);
}

/**
 * @tc.name: Read_CallbackErrorsAndOversize_MapStatusAndReleaseSlot
 * @tc.desc: Verify callback errors map correctly and no failed operation leaks a read slot.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Read_CallbackErrorsAndOversize_MapStatusAndReleaseSlot, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    std::vector<uint8_t> bytes;
    context_.readStatus = UDMF_E_INVALID_PARAM;
    EXPECT_EQ(provider_->Read("file", 0, 1, bytes), -EINVAL);
    context_.readStatus = UDMF_ERR;
    EXPECT_EQ(provider_->Read("file", 0, 1, bytes), -EIO);
    context_.readStatus = UDMF_E_OK;
    context_.oversize = true;
    EXPECT_EQ(provider_->Read("file", 0, 1, bytes), -EINVAL);
    context_.oversize = false;
    EXPECT_EQ(provider_->Read("file", 0, 1, bytes), 0);
    EXPECT_EQ(bytes, (std::vector<uint8_t>{ 0 }));
}

/**
 * @tc.name: Cancel_InvalidLists_RejectBeforeCallback
 * @tc.desc: Verify count and every file ID are validated before canceling downloads.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Cancel_InvalidLists_RejectBeforeCallback, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    EXPECT_EQ(provider_->Cancel({}), 0);
    EXPECT_EQ(context_.cancelCalls, 0u);
    EXPECT_EQ(provider_->Cancel(std::vector<std::string>(4097, "id")), -EINVAL);
    EXPECT_EQ(provider_->Cancel({ "" }), -EINVAL);
    EXPECT_EQ(provider_->Cancel({ std::string(1025, 'i') }), -EINVAL);
    EXPECT_EQ(provider_->Cancel({ std::string("a\0b", 3) }), -EINVAL);
    EXPECT_EQ(context_.cancelCalls, 0u);
}

/**
 * @tc.name: Cancel_ValidListsAndCallbackErrors_PreserveIdsAndMapStatus
 * @tc.desc: Verify cancellation preserves IDs and maps application result codes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Cancel_ValidListsAndCallbackErrors_PreserveIdsAndMapStatus, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    EXPECT_EQ(provider_->Cancel({ "a", "b" }), 0);
    EXPECT_EQ(context_.canceledIds, (std::vector<std::string>{ "a", "b" }));
    EXPECT_EQ(provider_->Cancel(std::vector<std::string>(4096, "id")), 0);
    EXPECT_EQ(context_.canceledIds.size(), 4096u);
    context_.cancelStatus = UDMF_E_INVALID_PARAM;
    EXPECT_EQ(provider_->Cancel({ "a" }), -EINVAL);
    context_.cancelStatus = UDMF_ERR;
    EXPECT_EQ(provider_->Cancel({ "a" }), -EIO);
}

/**
 * @tc.name: Read_ConcurrentCallbacks_RejectNinthAndRecoverQuota
 * @tc.desc: Verify the process read quota is eight and returns to full availability after completion.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Read_ConcurrentCallbacks_RejectNinthAndRecoverQuota, TestSize.Level0)
{
    ASSERT_NE(provider_, nullptr);
    context_.holdReads = true;
    std::vector<int32_t> results(8, -EIO);
    std::vector<std::thread> threads;
    for (size_t index = 0; index < results.size(); ++index) {
        threads.emplace_back([&, index] {
            std::vector<uint8_t> bytes;
            results[index] = provider_->Read("file", 0, 1, bytes);
        });
    }
    bool ready = false;
    {
        std::unique_lock<std::mutex> lock(context_.mutex);
        ready = context_.condition.wait_for(lock, std::chrono::seconds(2), [&] { return context_.readCalls == 8; });
    }
    std::vector<uint8_t> bytes;
    int32_t rejected = ready ? provider_->Read("file", 0, 1, bytes) : -ETIMEDOUT;
    {
        std::lock_guard<std::mutex> lock(context_.mutex);
        context_.releaseReads = true;
    }
    context_.condition.notify_all();
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(ready);
    EXPECT_EQ(rejected, -EAGAIN);
    EXPECT_TRUE(std::all_of(results.begin(), results.end(), [](int32_t result) { return result == 0; }));
    EXPECT_EQ(provider_->Read("file", 0, 1, bytes), 0);
}

/**
 * @tc.name: VirtualItem_InvalidStructId_RejectWithoutDestroyingHandle
 * @tc.desc: Verify wrong identifiers on valid wrapper objects are rejected without taking ownership.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, VirtualItem_InvalidStructId_RejectWithoutDestroyingHandle, TestSize.Level0)
{
    OH_UdmfVirtualItem invalid{ 0, {}, {} };
    EXPECT_EQ(OH_UdmfVirtualItem_SetFileSize(&invalid, 0), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_ClearFileSize(&invalid), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualItem_AddChild(&invalid, item_.get()), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdmfVirtualFileInfo_Create(&invalid, &callbacks_, &context_, OnFinalize), nullptr);
    OH_UdmfVirtualItem_Destroy(&invalid);
    EXPECT_EQ(invalid.entry_.size, -1);
}

/**
 * @tc.name: VirtualInfo_InvalidStructIdOrEmptyState_RejectUriAttachment
 * @tc.desc: Verify corrupt wrapper identifiers and absent callback state cannot be attached.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, VirtualInfo_InvalidStructIdOrEmptyState_RejectUriAttachment, TestSize.Level0)
{
    UriPtr uri(OH_UdsFileUri_Create(), OH_UdsFileUri_Destroy);
    ASSERT_NE(uri, nullptr);
    OH_UdmfVirtualFileInfo invalid{ 0, info_->info_ };
    OH_UdmfVirtualFileInfo empty;
    EXPECT_EQ(OH_UdsFileUri_SetVirtualEntry(uri.get(), &invalid), UDMF_E_INVALID_PARAM);
    EXPECT_EQ(OH_UdsFileUri_SetVirtualEntry(uri.get(), &empty), UDMF_E_INVALID_PARAM);
    OH_UdmfVirtualFileInfo_Destroy(&invalid);
    EXPECT_EQ(context_.finalized, 0u);
}

/**
 * @tc.name: Registry_MissingArguments_DoNotRetainProvider
 * @tc.desc: Verify attachment requires a file, provider and owner context.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Registry_MissingArguments_DoNotRetainProvider, TestSize.Level0)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    EXPECT_FALSE(VirtualEntryAttachmentRegistry::Attach(nullptr, item_->entry_, provider_->AsObject(), &owner));
    EXPECT_FALSE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, nullptr, &owner));
    EXPECT_FALSE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, provider_->AsObject(), nullptr));
}

/**
 * @tc.name: Registry_DetachOwner_LeaveOtherOwnersAlive
 * @tc.desc: Verify detach releases only providers belonging to the requested owner.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Registry_DetachOwner_LeaveOtherOwnersAlive, TestSize.Level0)
{
    auto first = std::make_shared<File>();
    auto second = std::make_shared<File>();
    AttachmentOwner firstOwner;
    AttachmentOwner secondOwner;
    auto firstProvider = CreateNdkVirtualEntryProvider(info_->info_);
    auto secondProvider = CreateNdkVirtualEntryProvider(info_->info_);
    wptr<IRemoteObject> firstWeak(firstProvider->AsObject());
    wptr<IRemoteObject> secondWeak(secondProvider->AsObject());
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(first, item_->entry_, firstProvider->AsObject(), &firstOwner));
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(
        second, item_->entry_, secondProvider->AsObject(), &secondOwner));
    firstProvider = nullptr;
    secondProvider = nullptr;
    EXPECT_NE(firstWeak.promote(), nullptr);
    EXPECT_NE(secondWeak.promote(), nullptr);
    VirtualEntryAttachmentRegistry::Detach(&firstOwner);
    EXPECT_EQ(firstWeak.promote(), nullptr);
    EXPECT_NE(secondWeak.promote(), nullptr);
    VirtualEntryAttachmentRegistry::Detach(&secondOwner);
    EXPECT_EQ(secondWeak.promote(), nullptr);
}

/**
 * @tc.name: Registry_ExpiredFile_PurgeProviderOnNextAttachment
 * @tc.desc: Verify weak file ownership does not keep a stale provider after the next registry update.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Registry_ExpiredFile_PurgeProviderOnNextAttachment, TestSize.Level0)
{
    auto file = std::make_shared<File>();
    auto nextFile = std::make_shared<File>();
    AttachmentOwner owner;
    auto temporary = CreateNdkVirtualEntryProvider(info_->info_);
    wptr<IRemoteObject> weak(temporary->AsObject());
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, temporary->AsObject(), &owner));
    temporary = nullptr;
    file.reset();
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(nextFile, item_->entry_, provider_->AsObject(), &owner));
    EXPECT_EQ(weak.promote(), nullptr);
}

/**
 * @tc.name: Registry_ReplaceSameFile_ReleasePreviousProvider
 * @tc.desc: Verify replacing an attachment does not retain an obsolete provider.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, Registry_ReplaceSameFile_ReleasePreviousProvider, TestSize.Level0)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    auto previous = CreateNdkVirtualEntryProvider(info_->info_);
    wptr<IRemoteObject> weak(previous->AsObject());
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, previous->AsObject(), &owner));
    previous = nullptr;
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, provider_->AsObject(), &owner));
    EXPECT_EQ(weak.promote(), nullptr);
}

/**
 * @tc.name: SetData_NonDragVirtualFile_RejectEveryFileRecordKind
 * @tc.desc: Verify each supported file record kind rejects virtual entries outside drag before service access.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, SetData_NonDragVirtualFile_RejectEveryFileRecordKind, TestSize.Level0)
{
    CustomOption option;
    option.intention = UD_INTENTION_DATA_HUB;
    for (auto type : { FILE, IMAGE, VIDEO, AUDIO, FOLDER }) {
        SCOPED_TRACE(type);
        auto file = std::make_shared<File>(type, std::string("file:///placeholder"));
        AttachmentOwner owner;
        ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, provider_->AsObject(), &owner));
        UnifiedData data;
        data.AddRecord(file);
        std::string key = "unchanged";
        EXPECT_EQ(UdmfClient::GetInstance().SetData(option, data, key), E_INVALID_PARAMETERS);
        EXPECT_EQ(key, "unchanged");
    }
}

/**
 * @tc.name: SetData_MultipleVirtualRoots_RejectBeforeChangingDetails
 * @tc.desc: Verify a drag containing two virtual providers is rejected without mutating caller records.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, SetData_MultipleVirtualRoots_RejectBeforeChangingDetails, TestSize.Level0)
{
    auto first = std::make_shared<File>();
    auto second = std::make_shared<File>();
    AttachmentOwner firstOwner;
    AttachmentOwner secondOwner;
    UDDetails details;
    details["source"] = std::string("keep");
    first->SetDetails(details);
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(first, item_->entry_, provider_->AsObject(), &firstOwner));
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(second, item_->entry_, provider_->AsObject(), &secondOwner));
    UnifiedData data;
    data.AddRecord(first);
    data.AddRecord(second);
    CustomOption option;
    option.intention = UD_INTENTION_DRAG;
    std::string key = "unchanged";
    EXPECT_EQ(UdmfClient::GetInstance().SetData(option, data, key), E_INVALID_PARAMETERS);
    EXPECT_EQ(key, "unchanged");
    EXPECT_EQ(first->GetDetails(), details);
}

/**
 * @tc.name: SetData_OrdinaryRecordBeforeVirtualFile_StillRejectWrongIntention
 * @tc.desc: Verify normal records are skipped while locating the attached file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, SetData_OrdinaryRecordBeforeVirtualFile_StillRejectWrongIntention, TestSize.Level0)
{
    auto file = std::make_shared<File>();
    AttachmentOwner owner;
    ASSERT_TRUE(VirtualEntryAttachmentRegistry::Attach(file, item_->entry_, provider_->AsObject(), &owner));
    UnifiedData data;
    data.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("text")));
    data.AddRecord(file);
    CustomOption option;
    option.intention = UD_INTENTION_DATA_HUB;
    std::string key;
    EXPECT_EQ(UdmfClient::GetInstance().SetData(option, data, key), E_INVALID_PARAMETERS);
    EXPECT_TRUE(key.empty());
}

/**
 * @tc.name: CreateInfo_ContextlessKnownFile_AllowMissingStatAndFinalizer
 * @tc.desc: Verify known files support contextless callbacks and forward-compatible callback-table sizes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, CreateInfo_ContextlessKnownFile_AllowMissingStatAndFinalizer, TestSize.Level0)
{
    ASSERT_EQ(OH_UdmfVirtualItem_SetFileSize(item_.get(), 0), UDMF_E_OK);
    auto callbacks = callbacks_;
    callbacks.structSize = sizeof(callbacks) + 16;
    callbacks.onStat = nullptr;
    callbacks.onRead = [](void *, const char *, int64_t, uint32_t, uint8_t *, uint32_t *bytesRead) {
        *bytesRead = 0;
        return static_cast<int>(UDMF_E_OK);
    };
    callbacks.onCancel = [](void *, const char* const *, uint32_t) { return static_cast<int>(UDMF_E_OK); };
    InfoPtr info(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks, nullptr, nullptr),
        OH_UdmfVirtualFileInfo_Destroy);
    ASSERT_NE(info, nullptr);
    auto provider = CreateNdkVirtualEntryProvider(info->info_);
    ASSERT_NE(provider, nullptr);
    VirtualEntry entry;
    EXPECT_EQ(provider->Stat("file", entry), -EINVAL);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(provider->Read("file", 0, 1, bytes), 0);
    EXPECT_TRUE(bytes.empty());
    EXPECT_EQ(provider->Cancel({ "file" }), 0);
    EXPECT_FALSE(AttachNdkVirtualEntry(nullptr, info->info_));
}

/**
 * @tc.name: SetVirtualEntry_ReplaceInfo_FinalizeEachContextOnce
 * @tc.desc: Verify replacing a URI attachment releases the previous context without releasing the new one early.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(VirtualEntryCapiTest, SetVirtualEntry_ReplaceInfo_FinalizeEachContextOnce, TestSize.Level0)
{
    CallbackContext firstContext;
    CallbackContext secondContext;
    InfoPtr first(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks_, &firstContext, OnFinalize),
        OH_UdmfVirtualFileInfo_Destroy);
    InfoPtr second(OH_UdmfVirtualFileInfo_Create(item_.get(), &callbacks_, &secondContext, OnFinalize),
        OH_UdmfVirtualFileInfo_Destroy);
    UriPtr uri(OH_UdsFileUri_Create(), OH_UdsFileUri_Destroy);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_NE(uri, nullptr);
    ASSERT_EQ(OH_UdsFileUri_SetVirtualEntry(uri.get(), first.get()), UDMF_E_OK);
    first.reset();
    EXPECT_EQ(firstContext.finalized, 0u);
    ASSERT_EQ(OH_UdsFileUri_SetVirtualEntry(uri.get(), second.get()), UDMF_E_OK);
    EXPECT_EQ(firstContext.finalized, 1u);
    second.reset();
    EXPECT_EQ(secondContext.finalized, 0u);
    uri.reset();
    EXPECT_EQ(secondContext.finalized, 1u);
}
} // namespace OHOS::UDMF

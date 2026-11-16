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

import { describe, it, expect } from '@ohos/hypium';
import UDC from '@ohos.data.unifiedDataChannel';
import UTD from '@ohos.data.uniformTypeDescriptor';
import UDS from '@ohos.data.uniformDataStruct';
import { BusinessError } from '@ohos.base';

function createInfo(name: string = 'boundary.bin'): UDS.VirtualFileInfo {
  return {
    itemInfo: { name: name, type: 'file', id: 'boundary', size: 0, modifyTime: 0 },
    onRead: async (_id: string, _offset: number, _length: number): Promise<Uint8Array> => new Uint8Array(0)
  };
}

function createRecord(info: UDS.VirtualFileInfo): UDC.UnifiedRecord {
  const fileUri: UDS.FileUri = {
    uniformDataType: 'general.file-uri',
    oriUri: 'file:///virtual/boundary',
    fileType: 'general.file',
    virtualEntry: info
  };
  return new UDC.UnifiedRecord(UTD.UniformDataType.FILE_URI, fileUri);
}

function expectInvalidName(name: string): void {
  const info: UDS.VirtualFileInfo = createInfo(name);
  // Supply optional callbacks so only the name validation is exercised.
  info.onStat = async (_id: string): Promise<UDS.VirtualFileItem> =>
    ({ name: 'boundary.bin', type: 'file', id: 'boundary', size: 0, modifyTime: 0 });
  info.onCancel = async (_ids: Array<string>): Promise<void> => {};
  let code: number = 0;
  try {
    createRecord(info);
  } catch (error) {
    code = Number((error as BusinessError).code);
  }
  expect(code).assertEqual(401);
}

export default function StageUdmfVirtualEntryBoundaryTest(): void {
  describe('StageUdmfVirtualEntryBoundaryTest', function () {
    /**
     * @tc.name VirtualEntryNameEmbeddedNul
     * @tc.desc Reject embedded NUL without truncation.
     * @tc.type FUNC
     */
    it('VirtualEntryNameEmbeddedNul', 0, function () {
      expectInvalidName('a\u0000b');
    });

    /**
     * @tc.name VirtualEntryNameTrailingNul
     * @tc.desc Reject trailing NUL without truncation.
     * @tc.type FUNC
     */
    it('VirtualEntryNameTrailingNul', 0, function () {
      expectInvalidName('boundary.bin\u0000');
    });

    /**
     * @tc.name VirtualEntryCallbacksOmitted
     * @tc.desc Accept onRead without optional callbacks.
     * @tc.type FUNC
     */
    it('VirtualEntryCallbacksOmitted', 0, function () {
      expect(createRecord(createInfo()).getTypes().length > 0).assertTrue();
    });

    /**
     * @tc.name VirtualEntryCancelOmitted
     * @tc.desc Accept onStat when onCancel is absent.
     * @tc.type FUNC
     */
    it('VirtualEntryCancelOmitted', 0, function () {
      const info: UDS.VirtualFileInfo = createInfo();
      info.onStat = async (_id: string): Promise<UDS.VirtualFileItem> =>
        ({ name: 'boundary.bin', type: 'file', id: 'boundary', size: 0, modifyTime: 0 });
      expect(createRecord(info).getTypes().length > 0).assertTrue();
    });

    /**
     * @tc.name VirtualEntryCancelUndefined
     * @tc.desc Accept explicitly undefined onCancel.
     * @tc.type FUNC
     */
    it('VirtualEntryCancelUndefined', 0, function () {
      const info: UDS.VirtualFileInfo = createInfo();
      info.onCancel = undefined;
      expect(createRecord(info).getTypes().length > 0).assertTrue();
    });

    /**
     * @tc.name VirtualEntryStatOmitted
     * @tc.desc Accept onCancel when onStat is absent.
     * @tc.type FUNC
     */
    it('VirtualEntryStatOmitted', 0, function () {
      const info: UDS.VirtualFileInfo = createInfo();
      info.onCancel = async (_ids: Array<string>): Promise<void> => {};
      expect(createRecord(info).getTypes().length > 0).assertTrue();
    });

    /**
     * @tc.name VirtualEntryUnicodeName
     * @tc.desc Preserve valid multibyte names.
     * @tc.type FUNC
     */
    it('VirtualEntryUnicodeName', 0, function () {
      expect(createRecord(createInfo('文'.repeat(85))).getTypes().length > 0).assertTrue();
    });
  });
}

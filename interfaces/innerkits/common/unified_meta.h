/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef UNIFIED_META_H
#define UNIFIED_META_H

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "string_ex.h"

namespace OHOS {
namespace UDMF {
enum UDType : int32_t {
    ENTITY = 0,
    OBJECT,
    COMPOSITE_OBJECT,
    TEXT,
    PLAIN_TEXT,
    HTML,
    HYPERLINK,
    XML,
    SOURCE_CODE,
    SCRIPT,
    SHELL_SCRIPT,
    CSH_SCRIPT,
    PERL_SCRIPT,
    PHP_SCRIPT,
    PYTHON_SCRIPT,
    RUBY_SCRIPT,
    TYPE_SCRIPT,
    JAVA_SCRIPT,
    C_HEADER,
    C_SOURCE,
    C_PLUS_PLUS_HEADER,
    C_PLUS_PLUS_SOURCE,
    JAVA_SOURCE,
    EBOOK,
    EPUB,
    AZW,
    AZW3,
    KFX,
    MOBI,
    MEDIA,
    IMAGE,
    JPEG,
    PNG,
    RAW_IMAGE,
    TIFF,
    BMP,
    ICO,
    PHOTOSHOP_IMAGE,
    AI_IMAGE,
    WORD_DOC,
    EXCEL,
    PPT,
    PDF,
    POSTSCRIPT,
    ENCAPSULATED_POSTSCRIPT,
    VIDEO,
    AVI,
    MPEG,
    MPEG4,
    VIDEO_3GPP,
    VIDEO_3GPP2,
    WINDOWS_MEDIA_WM,
    WINDOWS_MEDIA_WMV,
    WINDOWS_MEDIA_WMP,
    AUDIO,
    AAC,
    AIFF,
    ALAC,
    FLAC,
    MP3,
    OGG,
    PCM,
    WINDOWS_MEDIA_WMA,
    WAVEFORM_AUDIO,
    WINDOWS_MEDIA_WMX,
    WINDOWS_MEDIA_WVX,
    WINDOWS_MEDIA_WAX,
    FILE,
    DIRECTORY,
    FOLDER,
    SYMLINK,
    ARCHIVE,
    BZ2_ARCHIVE,
    DISK_IMAGE,
    TAR_ARCHIVE,
    ZIP_ARCHIVE,
    JAVA_ARCHIVE,
    GNU_TAR_ARCHIVE,
    GNU_ZIP_ARCHIVE,
    GNU_ZIP_TAR_ARCHIVE,
    CALENDAR,
    CONTACT,
    DATABASE,
    MESSAGE,
    VCARD,
    NAVIGATION,
    LOCATION,
    SYSTEM_DEFINED_FORM,
    SYSTEM_DEFINED_RECORD,
    SYSTEM_DEFINED_APP_ITEM,
    SYSTEM_DEFINED_PIXEL_MAP,
    OPENHARMONY_ATOMIC_SERVICE,
    APPLICATION_DEFINED_RECORD,
    OPENHARMONY_PACKAGE,
    OPENHARMONY_HAP,
    FAX,
    XBITMAP_IMAGE,
    AU_AUDIO,
    AIFC_AUDIO,
    VCS,
    ICS,
    EXECUTABLE,
    FONT,
    TRUETYPE_FONT,
    TRUETYPE_COLLECTION_FONT,
    OPENTYPE_FONT,
    MARKDOWM,
    POSTSCRIPT_FONT,
    POSTSCRIPT_PFB_FONT,
    POSTSCRIPT_PFA_FONT,
    PORTABLE_EXECUTABLE,
    SUN_JAVA_CLASS,
    TRUEVISION_TGA_IMAGE,
    SGI_SGI_IMAGE,
    ILM_OPENEXR_IMAGE,
    KODAK_FLASHPIX_IMAGE,
    J2_JFX_FAX,
    JS_EFX_FAX,
    DIGIDESIGN_SD2_AUDIO,
    REALMEDIA,
    REALAUDIO,
    SMIL,
    STUFFIT_ARCHIVE,
    OPENXML,
    WORDPROCESSINGML_DOCUMENT,
    SPREADSHEETML_SHEET,
    PRESENTATIONML_PRESENTATION,
    OPENDOCUMENT,
    OPENDOCUMENT_TEXT,
    OPENDOCUMENT_SPREADSHEET,
    OPENDOCUMENT_PRESENTATION,
    OPENDOCUMENT_GRAPHICS,
    OPENDOCUMENT_FORMULA,
    OPENHARMONY_WANT,
    OPENHARMONY_HDOC,
    OPENHARMONY_HINOTE,
    OPENHARMONY_STYLED_STRING,
    UD_BUTT
};

static const std::unordered_map<int32_t, std::string> UD_TYPE_MAP {
    { ENTITY, "general.entity" },
    { OBJECT, "general.object" },
    { COMPOSITE_OBJECT, "general.composite-object" },
    { TEXT, "general.text" },
    { PLAIN_TEXT, "general.plain-text" },
    { HTML, "general.html" },
    { HYPERLINK, "general.hyperlink" },
    { XML, "general.xml" },
    { SOURCE_CODE, "general.source-code" },
    { SCRIPT, "general.script" },
    { SHELL_SCRIPT, "general.shell-script" },
    { CSH_SCRIPT, "general.csh-script" },
    { PERL_SCRIPT, "general.perl-script" },
    { PHP_SCRIPT, "general.php-script" },
    { PYTHON_SCRIPT, "general.python-script" },
    { RUBY_SCRIPT, "general.ruby-script" },
    { TYPE_SCRIPT, "general.type-script" },
    { JAVA_SCRIPT, "general.java-script" },
    { C_HEADER, "general.c-header" },
    { C_SOURCE, "general.c-source" },
    { C_PLUS_PLUS_HEADER, "general.c-plus-plus-header" },
    { C_PLUS_PLUS_SOURCE, "general.c-plus-plus-source" },
    { JAVA_SOURCE, "general.java-source" },
    { EBOOK, "general.ebook" },
    { EPUB, "general.epub" },
    { AZW, "com.amazon.azw" },
    { AZW3, "com.amazon.azw3" },
    { KFX, "com.amazon.kfx" },
    { MOBI, "com.amazon.mobi" },
    { MEDIA, "general.media" },
    { IMAGE, "general.image" },
    { JPEG, "general.jpeg" },
    { PNG, "general.png" },
    { RAW_IMAGE, "general.raw-image" },
    { TIFF, "general.tiff" },
    { BMP, "com.microsoft.bmp" },
    { ICO, "com.microsoft.ico" },
    { PHOTOSHOP_IMAGE, "com.adobe.photoshop-image" },
    { AI_IMAGE, "com.adobe.illustrator.ai-image" },
    { WORD_DOC, "com.microsoft.word.doc" },
    { EXCEL, "com.microsoft.excel.xls" },
    { PPT, "com.microsoft.powerpoint.ppt" },
    { PDF, "com.adobe.pdf" },
    { POSTSCRIPT, "com.adobe.postscript" },
    { ENCAPSULATED_POSTSCRIPT, "com.adobe.encapsulated-postscript" },
    { VIDEO, "general.video" },
    { AVI, "general.avi" },
    { MPEG, "general.mpeg" },
    { MPEG4, "general.mpeg-4" },
    { VIDEO_3GPP, "general.3gpp" },
    { VIDEO_3GPP2, "general.3gpp2" },
    { WINDOWS_MEDIA_WM, "com.microsoft.windows-media-wm" },
    { WINDOWS_MEDIA_WMV, "com.microsoft.windows-media-wmv" },
    { WINDOWS_MEDIA_WMP, "com.microsoft.windows-media-wmp" },
    { AUDIO, "general.audio" },
    { AAC, "general.aac" },
    { AIFF, "general.aiff" },
    { ALAC, "general.alac" },
    { FLAC, "general.flac" },
    { MP3, "general.mp3" },
    { OGG, "general.ogg" },
    { PCM, "general.pcm" },
    { WINDOWS_MEDIA_WMA, "com.microsoft.windows-media-wma" },
    { WAVEFORM_AUDIO, "com.microsoft.waveform-audio" },
    { WINDOWS_MEDIA_WMX, "com.microsoft.windows-media-wmx" },
    { WINDOWS_MEDIA_WVX, "com.microsoft.windows-media-wvx" },
    { WINDOWS_MEDIA_WAX, "com.microsoft.windows-media-wax" },
    { FILE, "general.file" },
    { DIRECTORY, "general.directory" },
    { FOLDER, "general.folder" },
    { SYMLINK, "general.symlink" },
    { ARCHIVE, "general.archive" },
    { BZ2_ARCHIVE, "general.bz2-archive" },
    { DISK_IMAGE, "general.disk-image" },
    { TAR_ARCHIVE, "general.tar-archive" },
    { ZIP_ARCHIVE, "general.zip-archive" },
    { JAVA_ARCHIVE, "com.sun.java-archive" },
    { GNU_TAR_ARCHIVE, "org.gnu.gnu-tar-archive" },
    { GNU_ZIP_ARCHIVE, "org.gnu.gnu-zip-archive" },
    { GNU_ZIP_TAR_ARCHIVE, "org.gnu.gnu-zip-tar-archive" },
    { CALENDAR, "general.calendar" },
    { CONTACT, "general.contact" },
    { DATABASE, "general.database" },
    { MESSAGE, "general.message" },
    { VCARD, "general.vcard" },
    { NAVIGATION, "general.navigation" },
    { LOCATION, "general.location" },
    { SYSTEM_DEFINED_RECORD, "SystemDefinedType" },
    { SYSTEM_DEFINED_FORM, "openharmony.form" },
    { SYSTEM_DEFINED_APP_ITEM, "openharmony.app-item" },
    { SYSTEM_DEFINED_PIXEL_MAP, "openharmony.pixel-map" },
    { OPENHARMONY_ATOMIC_SERVICE, "openharmony.atomic-service" },
    { APPLICATION_DEFINED_RECORD, "ApplicationDefinedType" },
    { OPENHARMONY_PACKAGE, "openharmony.package" },
    { OPENHARMONY_HAP, "openharmony.hap" },
    { FAX, "general.fax" },
    { XBITMAP_IMAGE, "general.xbitmap-image" },
    { AU_AUDIO, "general.au-audio" },
    { AIFC_AUDIO, "general.aifc-audio" },
    { VCS, "general.vcs" },
    { ICS, "general.ics" },
    { EXECUTABLE, "general.executable" },
    { FONT, "general.font" },
    { TRUETYPE_FONT, "general.truetype-font" },
    { TRUETYPE_COLLECTION_FONT, "general.truetype-collection-font" },
    { OPENTYPE_FONT, "general.opentype-font" },
    { MARKDOWM, "general.markdown" },
    { POSTSCRIPT_FONT, "com.adobe.postscript-font" },
    { POSTSCRIPT_PFB_FONT, "com.adobe.postscript-pfb-font" },
    { POSTSCRIPT_PFA_FONT, "com.adobe.postscript-pfa-font" },
    { PORTABLE_EXECUTABLE, "com.microsoft.portable-excutable" },
    { SUN_JAVA_CLASS, "com.sun.java-class" },
    { TRUEVISION_TGA_IMAGE, "com.truevision.tga-image" },
    { SGI_SGI_IMAGE, "com.sgi.sgi-image" },
    { ILM_OPENEXR_IMAGE, "com.ilm.openexr-image" },
    { KODAK_FLASHPIX_IMAGE, "com.kodak.flashpix.image" },
    { J2_JFX_FAX, "com.j2.jfx-fax" },
    { JS_EFX_FAX, "com.js.efx-fax" },
    { DIGIDESIGN_SD2_AUDIO, "com.digidesign.sd2-audio" },
    { REALMEDIA, "com.real.realmedia" },
    { REALAUDIO, "com.real.realaudio" },
    { SMIL, "com.real.smil" },
    { STUFFIT_ARCHIVE, "com.allume.stuffit-archive" },
    { OPENXML, "org.openxmlformats.openxml" },
    { WORDPROCESSINGML_DOCUMENT, "org.openxmlformats.wordprocessingml.document" },
    { SPREADSHEETML_SHEET, "org.openxmlformats.spreadsheetml.sheet" },
    { PRESENTATIONML_PRESENTATION, "org.openxmlformats.presentationml.presentation" },
    { OPENDOCUMENT, "org.oasis.opendocument" },
    { OPENDOCUMENT_TEXT, "org.oasis.opendocument.text" },
    { OPENDOCUMENT_SPREADSHEET, "org.oasis.opendocument.spreadsheet" },
    { OPENDOCUMENT_PRESENTATION, "org.oasis.opendocument.presentation" },
    { OPENDOCUMENT_GRAPHICS, "org.oasis.opendocument.graphics" },
    { OPENDOCUMENT_FORMULA, "org.oasis.opendocument.formula" },
    { OPENHARMONY_WANT, "openharmony.want" },
    { OPENHARMONY_HDOC, "openharmony.hdoc" },
    { OPENHARMONY_HINOTE, "openharmony.hinote" },
    { OPENHARMONY_STYLED_STRING, "openharmony.styled-string" },
    { UD_BUTT, "INVALID"}
};

static const std::unordered_map<int32_t, std::string> JS_UD_TYPE_NAME_MAP {
    { ENTITY, "ENTITY" },
    { OBJECT, "OBJECT" },
    { COMPOSITE_OBJECT, "COMPOSITE_OBJECT" },
    { TEXT, "TEXT" },
    { PLAIN_TEXT, "PLAIN_TEXT" },
    { HTML, "HTML" },
    { HYPERLINK, "HYPERLINK" },
    { XML, "XML" },
    { SOURCE_CODE, "SOURCE_CODE" },
    { SCRIPT, "SCRIPT" },
    { SHELL_SCRIPT, "SHELL_SCRIPT" },
    { CSH_SCRIPT, "CSH_SCRIPT" },
    { PERL_SCRIPT, "PERL_SCRIPT" },
    { PHP_SCRIPT, "PHP_SCRIPT" },
    { PYTHON_SCRIPT, "PYTHON_SCRIPT" },
    { RUBY_SCRIPT, "RUBY_SCRIPT" },
    { TYPE_SCRIPT, "TYPE_SCRIPT" },
    { JAVA_SCRIPT, "JAVA_SCRIPT" },
    { C_HEADER, "C_HEADER" },
    { C_SOURCE, "C_SOURCE" },
    { C_PLUS_PLUS_HEADER, "C_PLUS_PLUS_HEADER" },
    { C_PLUS_PLUS_SOURCE, "C_PLUS_PLUS_SOURCE" },
    { JAVA_SOURCE, "JAVA_SOURCE" },
    { EBOOK, "EBOOK" },
    { EPUB, "EPUB" },
    { AZW, "AZW" },
    { AZW3, "AZW3" },
    { KFX, "KFX" },
    { MOBI, "MOBI" },
    { MEDIA, "MEDIA" },
    { IMAGE, "IMAGE" },
    { JPEG, "JPEG" },
    { PNG, "PNG" },
    { RAW_IMAGE, "RAW_IMAGE" },
    { TIFF, "TIFF" },
    { BMP, "BMP" },
    { ICO, "ICO" },
    { PHOTOSHOP_IMAGE, "PHOTOSHOP_IMAGE" },
    { AI_IMAGE, "AI_IMAGE" },
    { WORD_DOC, "WORD_DOC" },
    { EXCEL, "EXCEL" },
    { PPT, "PPT" },
    { PDF, "PDF" },
    { POSTSCRIPT, "POSTSCRIPT" },
    { ENCAPSULATED_POSTSCRIPT, "ENCAPSULATED_POSTSCRIPT" },
    { VIDEO, "VIDEO" },
    { AVI, "AVI" },
    { MPEG, "MPEG" },
    { MPEG4, "MPEG4" },
    { VIDEO_3GPP, "VIDEO_3GPP" },
    { VIDEO_3GPP2, "VIDEO_3GPP2" },
    { WINDOWS_MEDIA_WM, "WINDOWS_MEDIA_WM" },
    { WINDOWS_MEDIA_WMV, "WINDOWS_MEDIA_WMV" },
    { WINDOWS_MEDIA_WMP, "WINDOWS_MEDIA_WMP" },
    { AUDIO, "AUDIO" },
    { AAC, "AAC" },
    { AIFF, "AIFF" },
    { ALAC, "ALAC" },
    { FLAC, "FLAC" },
    { MP3, "MP3" },
    { OGG, "OGG" },
    { PCM, "PCM" },
    { WINDOWS_MEDIA_WMA, "WINDOWS_MEDIA_WMA" },
    { WAVEFORM_AUDIO, "WAVEFORM_AUDIO" },
    { WINDOWS_MEDIA_WMX, "WINDOWS_MEDIA_WMX" },
    { WINDOWS_MEDIA_WVX, "WINDOWS_MEDIA_WVX" },
    { WINDOWS_MEDIA_WAX, "WINDOWS_MEDIA_WAX" },
    { FILE, "FILE" },
    { DIRECTORY, "DIRECTORY" },
    { FOLDER, "FOLDER" },
    { SYMLINK, "SYMLINK" },
    { ARCHIVE, "ARCHIVE" },
    { BZ2_ARCHIVE, "BZ2_ARCHIVE" },
    { DISK_IMAGE, "DISK_IMAGE" },
    { TAR_ARCHIVE, "TAR_ARCHIVE" },
    { ZIP_ARCHIVE, "ZIP_ARCHIVE" },
    { JAVA_ARCHIVE, "JAVA_ARCHIVE" },
    { GNU_TAR_ARCHIVE, "GNU_TAR_ARCHIVE" },
    { GNU_ZIP_ARCHIVE, "GNU_ZIP_ARCHIVE" },
    { GNU_ZIP_TAR_ARCHIVE, "GNU_ZIP_TAR_ARCHIVE" },
    { CALENDAR, "CALENDAR" },
    { CONTACT, "CONTACT" },
    { DATABASE, "DATABASE" },
    { MESSAGE, "MESSAGE" },
    { VCARD, "VCARD" },
    { NAVIGATION, "NAVIGATION" },
    { LOCATION, "LOCATION" },
    { SYSTEM_DEFINED_RECORD, "SYSTEM_DEFINED_RECORD" },
    { SYSTEM_DEFINED_FORM, "OPENHARMONY_FORM" },
    { SYSTEM_DEFINED_APP_ITEM, "OPENHARMONY_APP_ITEM" },
    { SYSTEM_DEFINED_PIXEL_MAP, "OPENHARMONY_PIXEL_MAP" },
    { OPENHARMONY_ATOMIC_SERVICE, "OPENHARMONY_ATOMIC_SERVICE" },
    { APPLICATION_DEFINED_RECORD, "APPLICATION_DEFINED_RECORD" },
    { OPENHARMONY_PACKAGE, "OPENHARMONY_PACKAGE" },
    { OPENHARMONY_HAP, "OPENHARMONY_HAP" },
    { FAX, "FAX" },
    { XBITMAP_IMAGE, "XBITMAP_IMAGE" },
    { AU_AUDIO, "AU_AUDIO" },
    { AIFC_AUDIO, "AIFC_AUDIO" },
    { VCS, "VCS" },
    { ICS, "ICS" },
    { EXECUTABLE, "EXECUTABLE" },
    { FONT, "FONT" },
    { TRUETYPE_FONT, "TRUETYPE_FONT" },
    { TRUETYPE_COLLECTION_FONT, "TRUETYPE_COLLECTION_FONT" },
    { OPENTYPE_FONT, "OPENTYPE_FONT" },
    { MARKDOWM, "MARKDOWM" },
    { POSTSCRIPT_FONT, "POSTSCRIPT_FONT" },
    { POSTSCRIPT_PFB_FONT, "POSTSCRIPT_PFB_FONT" },
    { POSTSCRIPT_PFA_FONT, "POSTSCRIPT_PFA_FONT" },
    { PORTABLE_EXECUTABLE, "PORTABLE_EXECUTABLE" },
    { SUN_JAVA_CLASS, "SUN_JAVA_CLASS" },
    { TRUEVISION_TGA_IMAGE, "TRUEVISION_TGA_IMAGE" },
    { SGI_SGI_IMAGE, "SGI_SGI_IMAGE" },
    { ILM_OPENEXR_IMAGE, "ILM_OPENEXR_IMAGE" },
    { KODAK_FLASHPIX_IMAGE, "KODAK_FLASHPIX_IMAGE" },
    { J2_JFX_FAX, "J2_JFX_FAX" },
    { JS_EFX_FAX, "JS_EFX_FAX" },
    { DIGIDESIGN_SD2_AUDIO, "DIGIDESIGN_SD2_AUDIO" },
    { REALMEDIA, "REALMEDIA" },
    { REALAUDIO, "REALAUDIO" },
    { SMIL, "SMIL" },
    { STUFFIT_ARCHIVE, "STUFFIT_ARCHIVE" },
    { OPENXML, "OPENXML" },
    { WORDPROCESSINGML_DOCUMENT, "WORDPROCESSINGML_DOCUMENT" },
    { SPREADSHEETML_SHEET, "SPREADSHEETML_SHEET" },
    { PRESENTATIONML_PRESENTATION, "PRESENTATIONML_PRESENTATION" },
    { OPENDOCUMENT, "OPENDOCUMENT" },
    { OPENDOCUMENT_TEXT, "OPENDOCUMENT_TEXT" },
    { OPENDOCUMENT_SPREADSHEET, "OPENDOCUMENT_SPREADSHEET" },
    { OPENDOCUMENT_PRESENTATION, "OPENDOCUMENT_PRESENTATION" },
    { OPENDOCUMENT_GRAPHICS, "OPENDOCUMENT_GRAPHICS" },
    { OPENDOCUMENT_FORMULA, "OPENDOCUMENT_FORMULA" },
    { OPENHARMONY_WANT, "OPENHARMONY_WANT" },
    { OPENHARMONY_HDOC, "OPENHARMONY_HDOC" },
    { OPENHARMONY_HINOTE, "OPENHARMONY_HINOTE" },
    { OPENHARMONY_HINOTE, "OPENHARMONY_STYLED_STRING" }
};

/*
 * UnifiedData variant definitions.
 */
using UDVariant = std::variant<int32_t, int64_t, bool, double, std::string, std::vector<uint8_t>>;
using UDDetails = std::map<std::string, UDVariant>;
/*
 * UnifiedData Intention.
 */
enum Intention : int32_t {
    UD_INTENTION_BASE = 0,
    UD_INTENTION_DRAG,
    UD_INTENTION_DATA_HUB,
    UD_INTENTION_BUTT,
};

static const std::unordered_map<int32_t, std::string> UD_INTENTION_MAP {
    { UD_INTENTION_DRAG, "drag" },
    { UD_INTENTION_DATA_HUB, "DataHub" },
};

static const std::unordered_map<int32_t, std::string> JS_UD_INTENTION_NAME_MAP {
    { UD_INTENTION_DATA_HUB, "DATA_HUB" },
};

class UnifiedDataUtils {
public:
    static bool IsValidType(int32_t value);
    static bool IsValidIntention(int32_t value);
    static size_t GetVariantSize(UDVariant &variant);
    static size_t GetDetailsSize(UDDetails &details);
    static bool IsPersist(const Intention &intention);
    static bool IsPersist(const std::string &intention);
    static Intention GetIntentionByString(const std::string &intention);
    static bool IsValidOptions(const std::string &key, std::string &intention);
};
} // namespace UDMF
} // namespace OHOS
#endif // UNIFIED_META_H
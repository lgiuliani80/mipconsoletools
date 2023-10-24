using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LLoydsMonitorFolderForDecrypt.MSGFileUtils
{
    // Refer to https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf for the complete list of tag property ids
    public enum MsgPropertyIds : ushort
    {
        PidTagNull = 0x0000, // PtypUnspecified
        PidTagBody = 0x1000, // PtypString
        PidTagBodyHtml = 0x1013, // PtypString
        PidTagAttachFilename = 0x3704, // PtypString
        PidTagClientSubmitTime = 0x0039, // PtypTime
        PidTagAttachNumber = 0x0E21, // PtypInteger32
        PidTagDisplayName = 0x3001, // PtypString
        PidTagAttachExtension = 0x3703, // PtypString
        PidTagAttachContentId = 0x3712, // PtypString
        PidTagAttachMimeTag = 0x370E, // PtypString
        PidTagLanguage = 0x3A0C, // PtypString
        PidTagRenderingPosition = 0x370B, // PtypInteger32
        PidTagAccessLevel = 0x0FF7, // PtypInteger32
        PidTagMessageDeliveryTime = 0x0E06, // PtypTime
        PidTagLastModificationTime = 0x3008, // PtypTime
        PidTagCreationTime = 0x3007, // PtypTime
        PidTagMessageSubmissionId = 0x0047, // PtypBinary
        PidTagSubject = 0x0037, // PtypString
        PidTagRecipientDisplayName = 0x5FF6, // PtypString
        PidTagDisplayTo = 0x0E04, // PtypString
        PidTagEmailAddress = 0x3003, // PtypString
        PidTagSenderName = 0x0C1A, // PtypString
        PidTagDisplayBcc = 0x0E02, // PtypString
        PidTagDisplayCc = 0x0E03, // PtypString
        PidTagAttachDataObject = 0x3701, // PtypObject
        PidTagAttachLongFilename = 0x3707, // PtypString
        PidTagSmtpAddress = 0x39FE, // PtypString
        PidTagTransportMessageHeaders = 0x007D, // PtypString
        PidTagSenderEmailAddress = 0x0C1F, // PtypString
        PidTagSentRepresentingName = 0x0042, // PtypString
        PidTagObjectType = 0x0FFE, // PtypInteger32
        PidTagAttachmentLinkId = 0x7FFA, // PtypInteger32
        PidTagAttachMethod = 0x3705, // PtypInteger32
        PidTagHasAttachments = 0x0E1B, // PtypBoolean
        PidTagNativeBody = 0x1016, // PtypInteger32
    }

    // Refer https://interoperability.blob.core.windows.net/files/MS-OXCDATA/%5bMS-OXCDATA%5d.pdf for the complete list of property types
    public enum MsgPropertyTypes : ushort
    {
        PtypUnspecified = 0x0000,
        PtypInteger16 = 0x0002,
        PtypInteger32 = 0x0003,
        PtypFloating32 = 0x0004,
        PtypFloating64 = 0x0005,
        PtypCurrency = 0x0006,
        PtypFloatingTime = 0x0007,
        PtypErrorCode = 0x000A,
        PtypBoolean = 0x000B,
        PtypInteger64 = 0x0014,
        PtypString = 0x001F,
        PtypString8 = 0x001E,
        PtypTime = 0x0040,
        PtypGuid = 0x0048,
        PtypServerId = 0x00FB,
        PtypRestriction = 0x00FD,
        PtypRuleAction = 0x00FE,
        PtypBinary = 0x0102,
        PtypMultipleInteger16 = 0x1002,
        PtypMultipleInteger32 = 0x1003,
        PtypMultipleFloating32 = 0x1004,
        PtypMultipleFloating64 = 0x1005,
        PtypMultipleCurrency = 0x1006,
        PtypMultipleFloatingTime = 0x1007,
        PtypMultipleInteger64 = 0x1014,
        PtypMultipleString = 0x101F,
        PtypMultipleString8 = 0x101E,
        PtypMultipleTime = 0x1040,
        PtypMultipleGuid = 0x1048,
        PtypMultipleBinary = 0x1102,
        PtypNull = 0x0001,
        PtypObject = 0x000D, // Or PtypEmbeddedTable
    }

    [Flags]
    public enum MsgPropertyFlags : uint
    {
        MANDATORY= 0x00000001,
        READABLE = 0x00000002,
        WRITABLE = 0x00000004,
        READWRITE = READABLE | WRITABLE,
    }
}

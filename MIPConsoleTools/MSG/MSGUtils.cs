using OpenMcdf;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace MIPConsoleTools
{
    public static class MSGUtils
    {
        public static void EmplaceAttachmentInMsgFile(string templateFile, byte[] newAttachment, Stream outputStream)
        {
            using var fs = File.OpenRead(templateFile);
            using var cf = new CompoundFile(fs, CFSUpdateMode.Update, CFSConfiguration.SectorRecycle | CFSConfiguration.NoValidationException | CFSConfiguration.EraseFreeSectors);
            var attachmentsStorage = cf.RootStorage.GetStorage("__attach_version1.0_#00000000");
            attachmentsStorage.GetStream("__substg1.0_37010102").SetData(newAttachment);
            cf.Save(outputStream);
        }
    }
}

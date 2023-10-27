using LLoydsMonitorFolderForDecrypt.MSGFileUtils;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.Exceptions;
using Microsoft.InformationProtection.File;
using MsgReader.Outlook;
using OpenMcdf;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Mail;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static LLoydsMonitorFolderForDecrypt.MSGFileUtils.MsgFileUtils;
using MEL = Microsoft.Extensions.Logging;
using MIPL = Microsoft.InformationProtection;

namespace MIPConsoleTools
{
    public class MIPMain : IDisposable
    {
        const string MSG_ATTACHMENTS_LANGUAGE = "EnUs";
        const string HTML_RFT_PREAMBLE = "{\\rtf1\\ansi\\fromhtml1 {\\*\\htmltag ";

        readonly FileProfileSettings _profileSettings;
        readonly FileEngineSettings _engineSettings;
        readonly MipContext _mipContext;

        readonly IFileProfile _fileProfile;
        readonly IFileEngine _fileEngine;
        readonly ILogger _logger;

        public bool AppendSensitivityLabelToNames { get; set; }
        public string? MSGTemplateFile { get; set; }

        public MIPMain(ILogger logger, MIPL.LogLevel logLevel, string tenantId, string clientId, string appName, string appVersion, string username, string clientSecretOrCertificate, string locale = "en-US", string mipDataDir = "mip_data", string? delegatedUser = null, bool isInteractive = false)
        {
            _logger = logger;

            try
            {
                // Initialize Wrapper for File SDK operations.
                MIP.Initialize(MipComponent.File);

                // Create ApplicationInfo, setting the clientID from Azure AD App Registration as the ApplicationId.
                ApplicationInfo appInfo = new()
                {
                    ApplicationId = clientId,
                    ApplicationName = appName,
                    ApplicationVersion = appVersion
                };

                // Instantiate the AuthDelegateImpl object, passing in AppInfo.
                AuthDelegateImplementation authDelegate = new(logger, appInfo, tenantId, clientSecretOrCertificate, isInteractive);

                // Create MipConfiguration Object
                MipConfiguration mipConfiguration = new(appInfo, mipDataDir, logLevel, false)
                {
                    LoggerDelegateOverride = new MIPLoggerDelegate(logger),
                    DiagnosticOverride = new DiagnosticConfiguration
                    {
                        IsMinimalTelemetryEnabled = true
                    }
                };

                // Create MipContext using Configuration
                _mipContext = MIP.CreateMipContext(mipConfiguration);

                // Initialize and instantiate the File Profile.
                // Create the FileProfileSettings object.
                // Initialize file profile settings to create/use local state.
                _profileSettings = new FileProfileSettings(_mipContext,
                                      CacheStorageType.OnDiskEncrypted,
                                      new ConsentDelegateImplementation());

                // Load the Profile async and wait for the result.
                _fileProfile = Task.Run(async () => await MIP.LoadFileProfileAsync(_profileSettings)).Result;

                _engineSettings = new FileEngineSettings(username, authDelegate, "", locale);
                _engineSettings.Cloud = Cloud.Commercial;
                _engineSettings.Identity = new Identity(username);
                if (!string.IsNullOrWhiteSpace(delegatedUser))
                    _engineSettings.DelegatedUserEmail = delegatedUser;  // NOT REQUIRED IN CASE OF Content.SuperUser APPLICATION PERMISSION
                _engineSettings.CustomSettings = new List<KeyValuePair<string, string>> {
                    KeyValuePair.Create("enable_msg_file_type", "true")
                };

                _fileEngine = Task.Run(async () => await _fileProfile.AddEngineAsync(_engineSettings)).Result;
            }
            catch (Win32Exception w32ex)
            {
                logger.LogError($"Win32Exception: code/hresult={w32ex.ErrorCode} / hresult={w32ex.HResult} / errno={w32ex.NativeErrorCode}  -> ie {w32ex.InnerException}");
                throw;
            }
        }

        ~MIPMain()
        {
            Dispose();
        }

        public async Task<bool> DecryptFileAsync(string msgFileInput, Stream decrypted)
        {
            static async Task CopyToDestinationAsync(string source, Stream destination)
            {
                using var fs = File.OpenRead(source);
                await fs.CopyToAsync(destination);
            }

            try
            {
                using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);
                var s = await fileHandler.GetDecryptedTemporaryFileAsync();
                await CopyToDestinationAsync(s, decrypted);
                return true;
            }
            catch (NotSupportedException ex) when (ex.Message.StartsWith("File is not protected"))
            {
                await CopyToDestinationAsync(msgFileInput, decrypted);
                return false;
            }
            catch (BadInputException ex)
            {
                _logger.LogWarning(ex, "BadInputException while trying OME decryption of {fileName}", msgFileInput);
                await CopyToDestinationAsync(msgFileInput, decrypted);
                return false;
            }
        }

        public async Task<string> RecursiveDecryptAsync(string msgFileInput, string msgFileOutput, bool renameOutput)
        {
            using var output = await RecursiveProcessForDecryptionAsync(msgFileInput);
            
            if (output.Label != null && renameOutput)
            {
                msgFileOutput = Path.Combine(Path.GetDirectoryName(msgFileOutput)!, $"[{output.Label}]{Path.GetFileName(msgFileOutput)}");
            }
            
            File.Copy(output, msgFileOutput, overwrite: true);

            return msgFileOutput;
        }

        public record FileNameWrapper(string FileName, bool DeleteAtDispose) : IDisposable
        {
            public string? Label { get; set; }
            public void Dispose()
            {
                if (DeleteAtDispose)
                {
                    try { File.Delete(FileName); } catch { }
                }
                GC.SuppressFinalize(this);
            }

            public static implicit operator string(FileNameWrapper w) => w.FileName;
        }

        public record TempFileWrapper(string OriginalFileName) 
            : FileNameWrapper(Path.Combine(Path.GetTempPath(), $"att-{Guid.NewGuid()}-{OriginalFileName}"), true)
        {
        }

        public class TempDirWrapper : IDisposable
        {
            public string DirectoryName { get; init; }

            public TempDirWrapper(string directoryName = "")
            {
                DirectoryName = Path.Combine(Path.GetTempPath(), $"attdir-{Guid.NewGuid()}{directoryName}");
                Directory.CreateDirectory(DirectoryName);
            }

            public void Dispose()
            {
                try { Directory.Delete(DirectoryName, recursive: true); } catch (Exception) { }
                GC.SuppressFinalize(this);
            }

            public static implicit operator string(TempDirWrapper w) => w.DirectoryName;
        }

        public record DecryptResult(string DecryptedFileName, bool WasDecrypted) 
            : FileNameWrapper(DecryptedFileName, WasDecrypted)
        {
        }

        public async Task<DecryptResult> DecryptFileAsync(string msgFileInput)
        {
            var label = await GetLabelAsync(msgFileInput);
            using var ms = new MemoryStream();
            var result = await DecryptFileAsync(msgFileInput, ms);
            if (result)
            {
                string tmpFile = Path.GetTempFileName();
                using var fs = File.Create(tmpFile);
                ms.Seek(0, SeekOrigin.Begin);
                await ms.CopyToAsync(fs);

                return new DecryptResult(tmpFile, true) { Label = label };
            }
            else
            {
                return new DecryptResult(msgFileInput, false) { Label = label };
            }
        }

        private async Task<FileNameWrapper> RecursiveProcessForDecryptionAsync(string containerFile)
        {
            var ext = Path.GetExtension(containerFile).ToLower();

            switch (ext)
            {
                case ".msg":
                    {
                        return await RecursiveDecryptMSGAsync(containerFile);
                    }

                case ".zip":
                    {
                        using var tmpFolder = new TempDirWrapper();
                        bool processed = false;
                        ZipFile.ExtractToDirectory(containerFile, tmpFolder);
                        foreach (var file in Directory.EnumerateFiles(tmpFolder, "*", SearchOption.AllDirectories))
                        {
                            using var decryptResult = await RecursiveProcessForDecryptionAsync(file);

                            if (decryptResult.DeleteAtDispose)
                            {
                                File.Move(decryptResult, file, overwrite: true);
                                processed = true;
                            }

                            if (AppendSensitivityLabelToNames && decryptResult.Label != null)
                            {
                                File.Move(file, Path.Combine(Path.GetDirectoryName(file)!, $"[{decryptResult.Label}]{Path.GetFileName(file)}"), overwrite: true);
                                processed = true;
                            }
                        }
                        if (processed)
                        {
                            var tmpZipToEmplace = new TempFileWrapper(Path.GetFileName(containerFile));
                            ZipFile.CreateFromDirectory(tmpFolder, tmpZipToEmplace);
                            return tmpZipToEmplace;
                        }
                        else
                        {
                            return new FileNameWrapper(containerFile, false);
                        }
                    }

                default:
                    return await DecryptFileAsync(containerFile);
            }
        }

        private static string FilterValid83Chars(string st)
        {
            return new string(st.ToCharArray().Where(x => char.IsAscii(x) && x != ' ' && x != '.').ToArray());
        }

        private static string Get83FileName(string fn)
        {
            var bn = Path.GetFileNameWithoutExtension(fn);
            var ext = Path.GetExtension(fn).TrimStart('.');
            var bnFiltered = FilterValid83Chars(bn);
            var extFilt = FilterValid83Chars(ext);

            ext = extFilt.Length > 3 ? extFilt[0..3] : extFilt;

            if (bnFiltered != bn || bn.Length > 8)
            {
                bn = (bnFiltered.Length > 6 ? bnFiltered[0..6] : bnFiltered) + "~1";
            }

            return $"{bn}.{ext}";
        }

        private async Task<FileNameWrapper> RecursiveDecryptMSGAsync(string msgFileInput)
        {
            void VisitEntries(CFStorage st, CFStorage? parent)
            {
                bool reVisit = false;
                bool isEmbedded = parent != null;

                st.VisitEntries(item =>
                {
                    if (reVisit) return;

                    if (item is CFStorage storage && storage.Name.StartsWith(ATTACHMENT_STORAGE_NAME_PREFIX))
                    {
                        try
                        {
                            var attachmentName = storage.GetStringPropertyFailIfNotFound(MsgPropertyIds.PidTagAttachLongFilename);

                            if (attachmentName.EndsWith(".rpmsg", StringComparison.InvariantCultureIgnoreCase))
                            {
                                if (MSGTemplateFile == null)
                                    throw new ArgumentException("MSGTemplateFile cannot be null if using recursive decryption on MSG files with attachments");

                                var cids = new List<string>();

                                var rpmsgBytes = storage.GetRawProperty(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary)!;
                                using var tmpMsgFile = new TempFileWrapper(".msg");
                                using (var fs = File.Create(tmpMsgFile))
                                {
                                    MSGUtils.EmplaceAttachmentInMsgFile(MSGTemplateFile, rpmsgBytes, fs);
                                }

                                var msgLabel = GetLabelAsync(tmpMsgFile).Result;
                                var inspectResult = InspectMSGAsync(tmpMsgFile).Result;

                                if (inspectResult != null)
                                {
                                    int? nativeBody = null;

                                    if (inspectResult.BodyType == BodyType.RTF)
                                    {
                                        var rtfBytes = Encoding.ASCII.GetBytes(inspectResult.Body);

                                        var rtfCompressed =  BitConverter.GetBytes(rtfBytes.Length + 12)
                                                     .Concat(BitConverter.GetBytes(rtfBytes.Length))
                                                     .Concat(Encoding.ASCII.GetBytes("MELA"))
                                                     .Concat(BitConverter.GetBytes(0))
                                                     .Concat(rtfBytes).ToArray();

                                        //nativeBody = 2; // RTF (compressed)
                                        st.SetRawProperty(isEmbedded, MsgPropertyIds.PidTagRtfCompressed, MsgPropertyTypes.PtypBinary, rtfCompressed, (uint)rtfCompressed.Length);
                                        
                                        if (inspectResult.Body.StartsWith(HTML_RFT_PREAMBLE))
                                        {
                                            var htmlCode = inspectResult.Body[HTML_RFT_PREAMBLE.Length..^2];
                                            var htmlCodeBytes = Encoding.ASCII.GetBytes(htmlCode);

                                            cids = Regex.Matches(inspectResult.Body, "\"cid:([^\"]+)\"").Where(x => x.Success).Select(x => x.Groups[1].Value).ToList();
                                            st.SetRawProperty(isEmbedded, MsgPropertyIds.PidTagBodyHtml, MsgPropertyTypes.PtypBinary, htmlCodeBytes, (uint)htmlCodeBytes.Length);
                                        }
                                    }
                                    else if (inspectResult.BodyType == BodyType.HTML)
                                    {
                                        var htmlCode = inspectResult.Body;
                                        var htmlCodeBytes = Encoding.ASCII.GetBytes(htmlCode);

                                        nativeBody = 3; // HTML
                                        cids = Regex.Matches(inspectResult.Body, "\"cid:([^\"]+)\"").Where(x => x.Success).Select(x => x.Groups[1].Value).ToList();
                                        st.RemoveProperty(isEmbedded, MsgPropertyIds.PidTagRtfCompressed, MsgPropertyTypes.PtypBinary);
                                        st.SetRawProperty(isEmbedded, MsgPropertyIds.PidTagBodyHtml, MsgPropertyTypes.PtypBinary, htmlCodeBytes, (uint)htmlCodeBytes.Length);
                                    }
                                    else
                                    {
                                        nativeBody = 1; // Plain text
                                        st.RemoveProperty(isEmbedded, MsgPropertyIds.PidTagBodyHtml, MsgPropertyTypes.PtypBinary);
                                        st.RemoveProperty(isEmbedded, MsgPropertyIds.PidTagRtfCompressed, MsgPropertyTypes.PtypBinary);
                                        st.SetStringProperty(isEmbedded, MsgPropertyIds.PidTagBody, inspectResult.Body);
                                    }

                                    if (msgLabel != null && AppendSensitivityLabelToNames)
                                    {
                                        var subject = st.GetStringProperty(MsgPropertyIds.PidTagSubject);
                                        st.SetStringProperty(isEmbedded, MsgPropertyIds.PidTagSubject, $"[{msgLabel}]{subject}");
                                        if (parent != null)
                                        {
                                            var dn = parent.GetStringProperty(MsgPropertyIds.PidTagDisplayName);
                                            parent.SetStringProperty(true, MsgPropertyIds.PidTagDisplayName, $"[{msgLabel}]{dn}");
                                        }
                                    }

                                    AttachmentProperties ap = storage.GetPrimitiveTypesProperties<AttachmentProperties>();
                                    var rpmsgCreationTime = ap.GetProperty(MsgPropertyIds.PidTagCreationTime, MsgPropertyTypes.PtypTime).GetValue<DateTime>();
                                    var rpmsgLastModificationTime = ap.GetProperty(MsgPropertyIds.PidTagLastModificationTime, MsgPropertyTypes.PtypTime).GetValue<DateTime>();

                                    st.Delete(storage.Name); // Remove the .rpmsg attachment

                                    // TODO: CHECK BEHAVIOUR WITH MESSAGES AS ATTACHMENTS!
                                    
                                    for (int i = 0; i < inspectResult.Attachments.Count; i++)
                                    {
                                        var att = inspectResult.Attachments[i];
                                        var attst = st.AddStorage($"{ATTACHMENT_STORAGE_NAME_PREFIX}{i:X8}");

                                        // Primitive types properties
                                        var pp = attst.GetPrimitiveTypesProperties<AttachmentProperties>();
                                        pp.GetProperty(MsgPropertyIds.PidTagAttachNumber, MsgPropertyTypes.PtypInteger32).SetValue(i);
                                        pp.GetProperty(MsgPropertyIds.PidTagAttachMethod, MsgPropertyTypes.PtypInteger32).SetValue(1); // afByValue: The PidTagAttachDataBinary property (section 2.2.2.7) contains the attachment data.
                                        pp.GetProperty(MsgPropertyIds.PidTagCreationTime, MsgPropertyTypes.PtypTime).SetValue(rpmsgCreationTime);
                                        pp.GetProperty(MsgPropertyIds.PidTagLastModificationTime, MsgPropertyTypes.PtypTime).SetValue(rpmsgLastModificationTime);
                                        pp.GetProperty(MsgPropertyIds.PidTagRenderingPosition, MsgPropertyTypes.PtypInteger32).SetValue(0xFFFFFFFF);
                                        pp.GetProperty(MsgPropertyIds.PidTagAccessLevel, MsgPropertyTypes.PtypInteger32).SetValue(0);
                                        attst.SetPrimitiveTypesProperties(pp);

                                        // String properties
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachFilename, Get83FileName(att.Name));
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachLongFilename, att.Name);
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachExtension, Path.GetExtension(att.Name));
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachMimeTag, MimeTypes.GetMimeType(att.Name));
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagDisplayName, att.Name);
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagLanguage, MSG_ATTACHMENTS_LANGUAGE);
                                        // HEURISTIC!
                                        if (i < cids.Count)
                                            attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachContentId, cids[i]);

                                        // Binary properties
                                        attst.SetRawProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary, att.Content, (uint)att.Content.Length);
                                    }

                                    TopLevelOrEmbeddedProperties p = isEmbedded ? 
                                        st.GetPrimitiveTypesProperties<EmbeddedMessageProperties>() : 
                                        st.GetPrimitiveTypesProperties<TopLevelProperties>();

                                    p.AttachmentCount = (uint)inspectResult.Attachments.Count;
                                    p.NextAttachmentID = (uint)inspectResult.Attachments.Count;
                                    p.GetProperty(MsgPropertyIds.PidTagHasAttachments, MsgPropertyTypes.PtypBoolean).SetValue(p.AttachmentCount > 0);

                                    if (nativeBody != null)
                                    {
                                        p.GetProperty(MsgPropertyIds.PidTagNativeBody, MsgPropertyTypes.PtypInteger32).SetValue(nativeBody.Value);
                                    }

                                    st.SetPrimitiveTypesProperties(p);
                                    

                                    reVisit = true;
                                }
                                return;
                            }

                            var attachment = storage.GetRawProperty(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary)!;
                            using var tmpAttachmentFile = new TempFileWrapper(attachmentName);
                            File.WriteAllBytes(tmpAttachmentFile, attachment);
                            using var tmpProcessesAttachmentFile = RecursiveProcessForDecryptionAsync(tmpAttachmentFile).Result;
                            if (tmpAttachmentFile.DeleteAtDispose)
                            {
                                var attachmentBytes = File.ReadAllBytes(tmpProcessesAttachmentFile);
                                storage.SetRawProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary, attachmentBytes, (uint)attachment.Length);
                            }
                            if (tmpProcessesAttachmentFile.Label != null && AppendSensitivityLabelToNames)
                            {
                                attachmentName = $"[{tmpProcessesAttachmentFile.Label}]{attachmentName}";
                                storage.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachLongFilename, attachmentName);
                                storage.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagDisplayName, attachmentName);
                            }
                        }
                        catch (CFItemNotFound)
                        {
                            try
                            {
                                var nestedMsg = storage.GetStorage("__substg1.0_3701000D");

                                VisitEntries(nestedMsg, storage);
                            }
                            catch { }
                        }
                    }
                }, recursive: false);

                if (reVisit)
                    VisitEntries(st, parent);
            }

            var output = await DecryptFileAsync(msgFileInput);
            using (var fs = File.Open(output, FileMode.Open))
            {
                using var cf = new CompoundFile(fs, CFSUpdateMode.Update, CFSConfiguration.SectorRecycle | CFSConfiguration.NoValidationException | CFSConfiguration.EraseFreeSectors);

                VisitEntries(cf.RootStorage, null);

                if (output.Label != null && AppendSensitivityLabelToNames)
                {
                    var originalSubject = cf.RootStorage.GetStringProperty(MsgPropertyIds.PidTagOriginalSubject);
                    var subject = cf.RootStorage.GetStringProperty(MsgPropertyIds.PidTagSubject) ?? "";
                    cf.RootStorage.SetStringProperty<TopLevelProperties>(MsgPropertyIds.PidTagSubject, $"[{output.Label}]{subject}");
                    if (originalSubject == null)
                    {
                        cf.RootStorage.SetStringProperty<TopLevelProperties>(MsgPropertyIds.PidTagOriginalSubject, subject);
                    }
                }

                cf.Commit();
            }

            return output;
        }

        public async Task<WholeMessage?> InspectMSGAsync(string msgFileInput)
        {
            WholeMessage? ret = null;
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);
            using var inspector = await fileHandler.InspectAsync();

            if (inspector.Type == InspectorType.Msg && inspector is IMsgInspector msg)
            {
                ret = new WholeMessage
                {
                    Body = DecodeString(msg.Body.ToArray(), (int)msg.CodePage),
                    BodyType = msg.BodyType,
                    Attachments = new List<WholeMessage.Attachment>()
                };
                
                foreach (var att in msg.Attachments)
                {
                    ret.Attachments.Add(new WholeMessage.Attachment
                    {
                        Name = att.LongName,
                        Content = att.Bytes.ToArray()
                    });
                }
            }

            return ret;
        }

        public ReadOnlyCollection<Label> GetLabels()
        {
            return _fileEngine.SensitivityLabels;
        }

        public async Task<string?> GetLabelAsync(string msgFileInput)
        {
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);
            
            try
            {
                if (fileHandler.Label == null)
                    return null;

                return $"{fileHandler.Label?.Label?.Parent?.Name} - {fileHandler.Label?.Label?.Name}";
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task SetLabelAsync(string msgFileInput, string msgFileOutput, Label label, string justification)
        {
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);

            fileHandler.SetLabel(label, new LabelingOptions
            {
                IsDowngradeJustified = true,
                JustificationMessage = justification
            }, new ProtectionSettings
            {

            });
            await fileHandler.CommitAsync(msgFileOutput);
        }

        public async Task<bool> RemoveLabelAsync(string msgFileInput, string msgFileOutput, string justification)
        {
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);
            
            try
            {
                fileHandler.DeleteLabel(new LabelingOptions
                {
                    JustificationMessage = justification,
                    IsDowngradeJustified = true
                });
                await fileHandler.CommitAsync(msgFileOutput);

                return true;
            }
            catch (NotSupportedException ex) when (ex.Message.StartsWith("File is not protected"))
            {
                return false;
            }
        }

        private static string DecodeString(byte[] payload, int codepage) 
            => Encoding.GetEncoding(codepage == 1200 ? 65001 : codepage).GetString(payload, 16, payload.Length - 16);

        public void Dispose()
        {
            _mipContext?.ShutDown();
            GC.SuppressFinalize(this);
        }
    }

    class MIPLoggerDelegate : ILoggerDelegateV3
    {
        readonly ILogger _logger;

        public MIPLoggerDelegate(ILogger logger)
        {
            _logger = logger;
        }

        public void Flush()
        {

        }

        public void Init(string storagePath)
        {

        }

        private static MEL.LogLevel LogLevelMapper(MIPL.LogLevel ll) => ll switch
        {
            MIPL.LogLevel.Error => MEL.LogLevel.Error,
            MIPL.LogLevel.Warning => MEL.LogLevel.Warning,
            MIPL.LogLevel.Info => MEL.LogLevel.Information,
            MIPL.LogLevel.Trace => MEL.LogLevel.Trace,
            _ => MEL.LogLevel.Debug
        };

        private static MIPL.LogLevel LowerServerityIfNeeded(string message, MIPL.LogLevel ll)
        {
            if (message.Contains("https://self.events.data.microsoft.com"))
                return MIPL.LogLevel.Trace;

            if (message.Contains("Unprotected msg file cannot be inspected"))
                return MIPL.LogLevel.Info;

            if (message.Contains("File is not protected"))
                return MIPL.LogLevel.Info;

            return ll;
        }

        private MIPL.LogLevel LowerServerityIfNeeded(LogMessageData logMessageData)
        {
            return LowerServerityIfNeeded(logMessageData.Message, logMessageData.LogLevel);
        }

        public void WriteToLog(LogMessageData logMessageData)
        {
            var ll = LowerServerityIfNeeded(logMessageData);

            _logger.Log(LogLevelMapper(ll), $"[[{logMessageData.FunctionName}:{logMessageData.LineNumber}]] {logMessageData.Message}");
        }
        
        public void WriteToLog(MIPL.LogLevel logLevel, string message, string functionName, string fileName, int lineNo)
        {
            var ll = LowerServerityIfNeeded(message, logLevel);

            _logger.Log(LogLevelMapper(ll), $"[[{functionName}:{lineNo}]] {message}");
        }

        public void WriteToLog(MIPL.LogLevel logLevel, string message, string functionName, string fileName, int lineNo, object loggerContext)
        {
            var ll = LowerServerityIfNeeded(message, logLevel);

            _logger.Log(LogLevelMapper(ll), $"[[{functionName}:{lineNo}]] {message}");
        }
    }

    public class WholeMessage
    {
        public string Body { get; set; } = null!;
        public BodyType BodyType { get; set; }
        public List<Attachment> Attachments { get; set; } = null!;

        public class Attachment
        {
            public string Name { get; set; } = null!;
            public byte[] Content { get; set; } = null!;
        }
    }
}

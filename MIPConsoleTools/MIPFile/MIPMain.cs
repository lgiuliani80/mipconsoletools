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
using System.Buffers.Binary;
using System.Threading.Tasks;
using static LLoydsMonitorFolderForDecrypt.MSGFileUtils.MsgFileUtils;
using MEL = Microsoft.Extensions.Logging;
using MIPL = Microsoft.InformationProtection;
using MIPConsoleTools.Utils;
using System.IO.Packaging;
using System.Globalization;

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
        public bool UseGetLabelById { get; set; } = true;

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
                    KeyValuePair.Create("enable_msg_file_type", "true"),
                    KeyValuePair.Create("container_decryption_option", "top")
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

        public async Task<string> RecursiveDecryptAsync(string msgFileInput, string msgFileOutput, bool renameOutput, ItemMetadata metadata)
        {
            using var output = await RecursiveProcessForDecryptionAsync(msgFileInput, metadata);
            
            if (output.Label != null && renameOutput)
            {
                msgFileOutput = Path.Combine(Path.GetDirectoryName(msgFileOutput)!, $"[{CleanFileName(output.Label)}]{Path.GetFileName(msgFileOutput)}");
            }
            
            File.Copy(output, msgFileOutput, overwrite: true);

            return msgFileOutput;
        }

        public async Task<DecryptResult> DecryptFileAsync(string msgFileInput, bool forceTemporaryOutput = false)
        {
            var label = await GetLabelAsync(msgFileInput);
            using var ms = new MemoryStream();
            var result = await DecryptFileAsync(msgFileInput, ms);
            if (result || forceTemporaryOutput)
            {
                string tmpFile = Path.Combine(Path.GetTempPath(), $"dec-{Guid.NewGuid()}{Path.GetExtension(msgFileInput)}");
                using var fs = File.Create(tmpFile);
                ms.Seek(0, SeekOrigin.Begin);
                await ms.CopyToAsync(fs);

                return new DecryptResult(tmpFile, true) { Label = label, WasDecrypted = result };
            }
            else
            {
                return new DecryptResult(msgFileInput, false) { Label = label };
            }
        }

        private async Task<FileNameWrapper> RecursiveProcessForDecryptionAsync(string containerFile, ItemMetadata meta)
        {
            var ext = Path.GetExtension(containerFile).ToLower();

            meta.FileName ??= Path.GetFileName(containerFile);
            meta.OriginalSize = new FileInfo(containerFile).Length;

            switch (ext)
            {
                case ".msg":
                    {
                        return await RecursiveDecryptMSGAsync(containerFile, meta);
                    }

                case ".zip":
                    {
                        using var tmpFolder = new TempDirWrapper();
                        bool processed = false;
                        ZipFile.ExtractToDirectory(containerFile, tmpFolder);
                        foreach (var file in Directory.EnumerateFiles(tmpFolder, "*", SearchOption.AllDirectories))
                        {
                            using var decryptResult = await RecursiveProcessForDecryptionAsync(file, meta.AppendChild());

                            if (decryptResult.DeleteAtDispose)
                            {
                                File.Move(decryptResult, file, overwrite: true);
                                processed = true;
                            }

                            if (AppendSensitivityLabelToNames && decryptResult.Label != null)
                            {
                                File.Move(file, Path.Combine(Path.GetDirectoryName(file)!, $"[{CleanFileName(decryptResult.Label)}]{Path.GetFileName(file)}"), overwrite: true);
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
                    var dr = await DecryptFileAsync(containerFile);
                    meta.IsEncrypted = dr.WasDecrypted;
                    meta.Label = dr.Label;
                    return dr;
            }
        }

        private static string CleanFileName(string fileName)
        {
            return Path.GetInvalidFileNameChars().Aggregate(fileName, (current, c) => current.Replace(c.ToString(), string.Empty));
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

        private static string HtmlFromRtf(string rtfHtml)
        {
            if (rtfHtml.StartsWith(HTML_RFT_PREAMBLE))
            {
                rtfHtml = Regex.Replace(rtfHtml[HTML_RFT_PREAMBLE.Length..], "}}\\s*$", "");
            }
            rtfHtml = rtfHtml.Replace("\\par", "\n");
            rtfHtml = rtfHtml.Replace("\\{", "{").Replace("\\}", "}");
            rtfHtml = rtfHtml.Replace("\\\\", "\\");

            var matches = Regex.Matches(rtfHtml, @"\\u[0-9a-fA-F]{4}");

            foreach (var m in matches.Cast<Match>())
            {
                var hex = m.Value[2..];
                if (int.TryParse(hex,  NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code))
                {
                    rtfHtml = rtfHtml.Replace(m.Value, new string((char)code, 1));
                }
            }

            matches = Regex.Matches(rtfHtml, "\\\\'[0-9a-fA-F]{2}");

            foreach (var m in matches.Cast<Match>())
            {
                var hex = m.Value[2..];
                if (int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code))
                {
                    rtfHtml = rtfHtml.Replace(m.Value, new string((char)code, 1));
                }
            }

            return rtfHtml;
        }

        private async Task<FileNameWrapper> RecursiveDecryptMSGAsync(string msgFileInput, ItemMetadata meta)
        {
            void VisitEntries(CFStorage st, CFStorage? parent, ItemMetadata md)
            {
                bool reVisit = false;
                bool isEmbedded = parent != null;

                if (md.OriginalSize == 0)
                {
                    var nestedSize = st.Size;
                    st.VisitEntries(item => nestedSize += item.Size, true);
                    md.OriginalSize = nestedSize;
                }

                var msgHeaders = st.GetStringProperty(MsgPropertyIds.PidTagTransportMessageHeaders);

                Match m;
                if (msgHeaders != null && 
                    md.Label == null && 
                    (m = Regex.Match(msgHeaders, @"MSIP_Label_([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})_", RegexOptions.IgnoreCase)).Success)
                {
                    md.Label = m.Groups[1].Value;

                    var lbl = UseGetLabelById ? _fileEngine.GetLabelById(md.Label) : GetAllLabels().FirstOrDefault(x => x.Id.ToLower() == md.Label.ToLower());
                    
                    if (lbl != null)
                    {
                        md.Label = string.Join(" - ", new string?[] {
                                            lbl.Parent?.Name,
                                            lbl.Name
                                        }.Where(x => !string.IsNullOrWhiteSpace(x)));
                    }
                }

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
                                    throw new ArgumentException($"{nameof(MSGTemplateFile)} cannot be null if using recursive decryption on MSG files with attachments");

                                var cids = new List<string>();

                                var rpmsgBytes = storage.GetRawProperty(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary)!;
                                using var tmpMsgFile = new TempFileWrapper(".msg");
                                using (var fs = File.Create(tmpMsgFile))
                                {
                                    MSGUtils.EmplaceAttachmentInMsgFile(MSGTemplateFile, rpmsgBytes, fs);
                                }

                                var inspectResult = InspectMSGAsync(tmpMsgFile).Result;

                                if (inspectResult != null)
                                {
                                    int? nativeBody = null;

                                    md.IsEncrypted = true;

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
                                            var htmlCode = HtmlFromRtf(inspectResult.Body);
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

                                    if (md.Label != null && AppendSensitivityLabelToNames)
                                    {
                                        var subject = st.GetStringProperty(MsgPropertyIds.PidTagSubject);
                                        st.SetStringProperty(isEmbedded, MsgPropertyIds.PidTagSubject, $"[{md.Label}]{subject}");
                                        if (parent != null)
                                        {
                                            var dn = parent.GetStringProperty(MsgPropertyIds.PidTagDisplayName);
                                            parent.SetStringProperty(true, MsgPropertyIds.PidTagDisplayName, $"[{md.Label}]{dn}");
                                        }
                                    }

                                    AttachmentProperties ap = storage.GetPrimitiveTypesProperties<AttachmentProperties>();
                                    var rpmsgCreationTime = ap.GetProperty(MsgPropertyIds.PidTagCreationTime, MsgPropertyTypes.PtypTime).GetValue<DateTime>();
                                    var rpmsgLastModificationTime = ap.GetProperty(MsgPropertyIds.PidTagLastModificationTime, MsgPropertyTypes.PtypTime).GetValue<DateTime>();

                                    TopLevelOrEmbeddedProperties p0 = isEmbedded ?
                                        st.GetPrimitiveTypesProperties<EmbeddedMessageProperties>() :
                                        st.GetPrimitiveTypesProperties<TopLevelProperties>();

                                    List<string> attachmentStorageNames = new();

                                    st.VisitEntries(item =>
                                    {
                                        if (item is CFStorage storage && storage.Name.StartsWith(ATTACHMENT_STORAGE_NAME_PREFIX))
                                        {
                                            attachmentStorageNames.Add(storage.Name);
                                        }
                                    }, false);

                                    attachmentStorageNames.ForEach(x =>
                                    {
                                        st.Delete(x);
                                    });

                                    int attachmentIndex = 0;
                                    int initialAttachmentIndex = attachmentIndex;
                                    List<CFStorage> renderableAttachments = new();

                                    for (int i = 0; i < inspectResult.Attachments.Count; i++)
                                    {
                                        var att = inspectResult.Attachments[i];
                                        var attst = st.AddStorage($"{ATTACHMENT_STORAGE_NAME_PREFIX}{attachmentIndex++:X8}");
                                        var ext = Path.GetExtension(att.Name);

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
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachExtension, ext);
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachMimeTag, MimeTypes.GetMimeType(att.Name));
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagDisplayName, att.Name);
                                        attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagLanguage, MSG_ATTACHMENTS_LANGUAGE);
                                        
                                        // HEURISTIC!
                                        var cid = cids.FirstOrDefault(x => x.StartsWith(att.Name + "@", StringComparison.OrdinalIgnoreCase));
                                        if (cid != null)
                                        {
                                            attst.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachContentId, cid);
                                            cids.Remove(cid);
                                        }
                                        else if (ext.ToLower() == ".png" || ext.ToLower() == ".jpg" || ext.ToLower() == ".jpeg" || ext.ToLower() == ".gif")
                                        {
                                            renderableAttachments.Add(attst);
                                        }

                                        // Binary properties
                                        attst.SetRawProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary, att.Content, (uint)att.Content.Length);
                                    }

                                    // Try to map all remaining CIDs to image attachments
                                    int cidIndex = 0;
                                    foreach (var ast in renderableAttachments)
                                    {
                                        if (cidIndex >= cids.Count)
                                            break;

                                        var cid = cids[cidIndex];
                                        ast.SetStringProperty<AttachmentProperties>(MsgPropertyIds.PidTagAttachContentId, cid);

                                        cidIndex++;
                                    }

                                    TopLevelOrEmbeddedProperties p = isEmbedded ? 
                                        st.GetPrimitiveTypesProperties<EmbeddedMessageProperties>() : 
                                        st.GetPrimitiveTypesProperties<TopLevelProperties>();

                                    p.AttachmentCount = (uint)attachmentIndex;
                                    p.NextAttachmentID = (uint)attachmentIndex;
                                    p.GetProperty(MsgPropertyIds.PidTagHasAttachments, MsgPropertyTypes.PtypBoolean).SetValue(attachmentIndex > 0);

                                    if (nativeBody != null)
                                    {
                                        p.GetProperty(MsgPropertyIds.PidTagNativeBody, MsgPropertyTypes.PtypInteger32).SetValue(nativeBody.Value);
                                    }

                                    st.SetPrimitiveTypesProperties(p);
                                    

                                    reVisit = true;
                                }
                                return;
                            }

                            var childMeta = md.AppendChild();
                            childMeta.FileName = attachmentName;
                            var attachment = storage.GetRawProperty(MsgPropertyIds.PidTagAttachDataObject, MsgPropertyTypes.PtypBinary)!;
                            using var tmpAttachmentFile = new TempFileWrapper(attachmentName);
                            File.WriteAllBytes(tmpAttachmentFile, attachment);
                            using var tmpProcessesAttachmentFile = RecursiveProcessForDecryptionAsync(tmpAttachmentFile, childMeta).Result;
                            if (tmpProcessesAttachmentFile.DeleteAtDispose)
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
                            var displayName = storage.GetStringProperty(MsgPropertyIds.PidTagDisplayName);

                            try
                            {
                                if (storage.TryGetStorage("__substg1.0_3701000D", out var nestedMsg))
                                {
                                    var childMeta = md.AppendChild();
                                    childMeta.FileName = displayName;
                                    VisitEntries(nestedMsg, storage, childMeta);
                                }
                            }
                            catch (Exception ex) 
                            {
                                _logger.LogError(ex, "Unable to process attachment '{attachmentName}' in storage {storage} - input file: '{input}'", displayName ?? "?", storage.Name, msgFileInput);
                                throw;
                            }
                        }
                    }
                }, recursive: false);

                if (reVisit)
                    VisitEntries(st, parent, md);
            }

            var output = await DecryptFileAsync(msgFileInput, forceTemporaryOutput: true);
            meta.Label = output.Label;
            meta.IsEncrypted = output.WasDecrypted;

            using (var fs = File.Open(output, FileMode.Open))
            {
                using var cf = new CompoundFile(fs, CFSUpdateMode.Update, CFSConfiguration.SectorRecycle | CFSConfiguration.NoValidationException | CFSConfiguration.EraseFreeSectors);

                VisitEntries(cf.RootStorage, null, meta);

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

                cf.RootStorage.ScanDuplicateProperties(cleanMethod: AbstractPrimitiveTypesProperties.CleanMethod.TakeLast);
                cf.RootStorage.FixPropertySizes();

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
                    Body = DecompressRTF(msg.Body.ToArray()),
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

        public IEnumerable<Label> GetAllLabels()
        {
            static IEnumerable<Label> RecursiveGetLabels(IReadOnlyCollection<Label> labels)
            {
                foreach (var label in labels)
                {
                    yield return label;

                    foreach (var l in RecursiveGetLabels(label.Children))
                    {
                        yield return l;
                    }
                }
            }

            return RecursiveGetLabels(_fileEngine.SensitivityLabels);
        }

        public async Task<string?> GetLabelAsync(string msgFileInput)
        {
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);
            
            try
            {
                if (fileHandler.Label == null)
                {
#if TRY_EXTRACT_LABEL_FROM_CONTENT_MARKER
                    var ext = Path.GetExtension(msgFileInput).ToLower();

                    switch (ext)
                    {
                        case ".docx":
                        case ".pptx":
                            {
                                using var pkg = Package.Open(msgFileInput, FileMode.Open, FileAccess.Read);
                                var custProps = pkg.GetPart(new Uri("/docProps/custom.xml", UriKind.Relative));
                                if (custProps != null)
                                {
                                    var xmldoc = new System.Xml.XmlDocument();
                                    var xmlnsmgr = new System.Xml.XmlNamespaceManager(xmldoc.NameTable);
                                    xmlnsmgr.AddNamespace("vt", "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes");
                                    xmlnsmgr.AddNamespace("p", "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties");
                                    xmldoc.Load(custProps.GetStream());
                                    var node = xmldoc.SelectSingleNode("//p:property/vt:lpwstr[starts-with(., 'Classification: ')]", xmlnsmgr);
                                    if (node != null)
                                    {
                                        return node.InnerText["Classification: ".Length..] + "_D";
                                    }
                                }
                            }
                            break;

                        case ".xlsx":
                        case ".xlsm":
                            {
                                using var pkg = Package.Open(msgFileInput, FileMode.Open, FileAccess.Read);
                                var sheet1 = pkg.GetPart(new Uri("/xl/worksheets/sheet1.xml", UriKind.Relative));
                                if (sheet1 != null)
                                {
                                    var xmldoc = new System.Xml.XmlDocument();
                                    var xmlnsmgr = new System.Xml.XmlNamespaceManager(xmldoc.NameTable);
                                    xmlnsmgr.AddNamespace("o", "http://schemas.openxmlformats.org/spreadsheetml/2006/main");
                                    xmldoc.Load(sheet1.GetStream());
                                    var node = xmldoc.SelectSingleNode("//o:oddHeader[contains(., 'Classification: ')]", xmlnsmgr);
                                    if (node != null)
                                    {
                                        var match = Regex.Match(node.InnerText, @"Classification: ([^&\r\n]+)");
                                        if (match.Success)
                                        {
                                            return match.Groups[1].Value + "_D";
                                        }
                                    }
                                }
                            }
                            break;
                    }
#endif
                    return null;
                }

                return string.Join(" - ", new string?[] { 
                    fileHandler.Label?.Label?.Parent?.Name, 
                    fileHandler.Label?.Label?.Name 
                }.Where(x => !string.IsNullOrWhiteSpace(x)));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task SetLabelAsync(string msgFileInput, string msgFileOutput, Label label, string justification, bool privilegedAssignment = true)
        {
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);

            fileHandler.SetLabel(label, new LabelingOptions
            {
                AssignmentMethod = privilegedAssignment ? AssignmentMethod.Privileged : AssignmentMethod.Auto,
                IsDowngradeJustified = !string.IsNullOrWhiteSpace(justification),
                JustificationMessage = justification
            }, new ProtectionSettings
            {

            });
            await fileHandler.CommitAsync(msgFileOutput);
        }

        public async Task<bool> RemoveLabelAsync(string msgFileInput, string msgFileOutput, string justification, bool privilegedAssignment = true)
        {
            using var fileHandler = await _fileEngine.CreateFileHandlerAsync(msgFileInput, msgFileInput, true);
            
            try
            {
                fileHandler.DeleteLabel(new LabelingOptions
                {
                    AssignmentMethod = privilegedAssignment ? AssignmentMethod.Privileged : AssignmentMethod.Auto,
                    IsDowngradeJustified = !string.IsNullOrWhiteSpace(justification),
                    JustificationMessage = justification
                });
                await fileHandler.CommitAsync(msgFileOutput);

                return true;
            }
            catch (NotSupportedException ex) when (ex.Message.StartsWith("File is not protected"))
            {
                return false;
            }
        }

        public static string DecompressRTF(byte[] payload)
        {
            const string INITIAL_DICTIONARY = "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";
            const uint UNCOMPRESSED_RTF = 0x414c454d;
            const uint COMPRESSED_RTF = 0x75465a4c;

            var st = new MemoryStream(payload);
            var dis = new BinaryReader(st);

            var compSize = dis.ReadUInt32();
            var rawSize = dis.ReadUInt32();
            var compType = dis.ReadUInt32();
            var crc = dis.ReadUInt32();

            if (compType == UNCOMPRESSED_RTF) 
            {
                return Encoding.UTF8.GetString(payload, 16, payload.Length - 16);
            } 
            else if (compType != COMPRESSED_RTF) 
            {
                if (payload.Take(16).All(x => x == 13 || x == 10 || x == 9 || x >= 32))
                {
                    // Apparently it's a plain text stream, without the 16 bytes header of the compressed RTF stream [PidTagRtfCompressed] --> let's decode all the stream as UTF-8
                    return Encoding.UTF8.GetString(payload);
                }
                else
                {
                    throw new IOException($"Invalid compression type: {compType:X8}");
                }
            }

            var sb = new StringBuilder();
            sb.Append(INITIAL_DICTIONARY);
            var writeOffset = sb.Length;
            var output = new StringBuilder();
            var endRunReached = false;

            while (!endRunReached)
            {
                var b = dis.ReadByte();

                for (int i = 0; i < 8; i++)
                {
                    if ((b & 1) == 0)
                    {
                        var c = dis.ReadByte();
                        output.Append((char)c);
                        if (writeOffset < 4096)
                        {
                            sb.Append((char)c);
                        }
                        else
                        {
                            sb[writeOffset & 0xFFF] = (char)c;
                        }
                        writeOffset++;
                    }
                    else
                    {
                        var dicReference = BinaryPrimitives.ReverseEndianness(dis.ReadUInt16());
                        var offset = (dicReference >> 4) & 0xFFF;
                        if (offset == (writeOffset & 0xFFF))
                        {
                            endRunReached = true;
                            break;
                        }
                        var length = (dicReference & 0xF) + 2;
                        for (int j = 0; j < length; j++)
                        {
                            var c = sb[offset & 0xFFF];
                            output.Append(c);
                            offset++;
                            if (writeOffset < 4096)
                            {
                                sb.Append(c);
                            }
                            else
                            {
                                sb[writeOffset & 0xFFF] = c;
                            }
                            writeOffset++;
                        }
                    }
                    b >>= 1;
                }
            }

            dis.Close();
            st.Close();

            return output.ToString();
        }

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

            if (message.Contains("Start calling error callback for API: file_get_decrypted_file_path_async"))
                return MIPL.LogLevel.Info;

            if (message.Contains("GetAppDataNode - Failed to get ID in PL app data section, parsing failed"))
                return MIPL.LogLevel.Info;

            if (message.Contains("GetAppDataNode - Failed to get TenantId in PL app data section, parsing failed"))
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

    public class ItemMetadata
    {
        public long OriginalSize { get; set; }
        public bool IsEncrypted { get; set; }
        public string? FileName { get; set; }
        public string? Label { get; set; }
        public List<ItemMetadata> Children { get; init; } = new();

        public ItemMetadata AppendChild()
        {
            var c = new ItemMetadata();
            Children.Add(c);
            return c;
        }
    }
}

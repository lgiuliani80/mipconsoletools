using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.Exceptions;
using Microsoft.InformationProtection.File;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

using MEL = Microsoft.Extensions.Logging;
using MIPL = Microsoft.InformationProtection;

namespace MIPConsoleTools
{
    public class MIPMain : IDisposable
    {
        readonly FileProfileSettings _profileSettings;
        readonly FileEngineSettings _engineSettings;
        readonly MipContext _mipContext;

        readonly IFileProfile _fileProfile;
        readonly IFileEngine _fileEngine;
        readonly ILogger _logger;

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
                _logger.LogWarning(ex, "BadInputException while trying OME descript of {fileName}", msgFileInput);
                await CopyToDestinationAsync(msgFileInput, decrypted);
                return false;
            }
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

        private MIPL.LogLevel LowerServerityIfNeeded(string message, MIPL.LogLevel ll)
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

    public static class BodyTypeExtensions
    {
        public static string GetMimeType(this BodyType bt) => bt switch
        {
            BodyType.HTML => "text/html",
            BodyType.TXT => "text/plain",
            BodyType.RTF => "application/rtf",
            BodyType.UNKNOWN or _ => "application/octet-stream"
        };
    }
}

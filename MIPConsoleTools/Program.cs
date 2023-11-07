using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MIPConsoleTools;
using System.Runtime.CompilerServices;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureLogging(logging => {
        logging.AddSimpleConsole(options =>
        {
            options.IncludeScopes = true;
            options.SingleLine = true;
            options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss.fff] ";
        });
    })
    .Build();

var config = host.Services.GetRequiredService<IConfiguration>();
var log = host.Services.GetRequiredService<ILogger<Program>>();
var miplog = host.Services.GetRequiredService<ILogger<MIPMain>>();
string input = null!, output = null!;
using var logScope = log.BeginScope("[mtid={tid,5}]", new ManagedThreadIdGenerator());

log.LogInformation("ClientId = {clientId}", config["MIP:ClientId"]);

MIPMain mip = new (
    miplog,
    config.GetValue<Microsoft.InformationProtection.LogLevel>("MIP:LogLevel"),
    config["MIP:TenantId"] ?? "common", 
    config["MIP:ClientId"] ?? AuthDelegateImplementation.AIP_CLIENT_ID,
    config["MIP:AppName"] ?? "AzureInformationProtectionClient", 
    config["MIP:AppVersion"] ?? "1.0",
    config["MIP:Username"]!, config["MIP:ClientSecret"]!, 
    delegatedUser: config["MIP:DelegatedUser"], 
    isInteractive: config.GetValue("MIP:IsInteractive", false)
);

bool result = false;

switch (config["action"])
{
    case "decrypt":
        input = config["input"]!;
        output = config["output"]!;
        
        if (input.EndsWith(".eml", StringComparison.InvariantCultureIgnoreCase))
        {
            var eml = MsgReader.Mime.Message.Load(new FileInfo(input));
            var wrappedMsg = Path.ChangeExtension(input, ".wrapped.msg");
            if (eml.Attachments.Count == 0 || !eml.Attachments[0].FileName.EndsWith(".rpmsg", StringComparison.InvariantCultureIgnoreCase))
            {
                log.LogWarning("Input file {input} is not an encrypted message!!", input);
                Environment.Exit(1);
            }
            
            using (var wrappedMsgFs = File.Create(wrappedMsg))
            {
                MSGUtils.EmplaceAttachmentInMsgFile(config["msgTemplate"]!, eml.Attachments[0].Body, wrappedMsgFs);
            }
            input = wrappedMsg;
        }
        else if (input.EndsWith(".rpmsg", StringComparison.InvariantCultureIgnoreCase))
        {
            var wrappedMsg = Path.ChangeExtension(input, ".wrapped.msg");

            using (var wrappedMsgFs = File.Create(wrappedMsg))
            {
                MSGUtils.EmplaceAttachmentInMsgFile(config["msgTemplate"]!, File.ReadAllBytes(input), wrappedMsgFs);
            }
            input = wrappedMsg;
        }

        if (config["msgTemplate"] != null && config.GetValue("recursive", true))
        {
            mip.MSGTemplateFile = config["msgTemplate"]!;
            mip.AppendSensitivityLabelToNames = config.GetValue("appendSensitivityLabelToNames", false);
            await mip.RecursiveDecryptAsync(input, output, true);
        }
        else
        {
            using var fs = File.Create(output);
            result = await mip.DecryptFileAsync(input, fs);

            if (!result)
            {
                log.LogError("File {input} does not appear to be encrypted", input);
            }
        }
        break;

    case "listlabels":
        var labels = mip.GetLabels();
        foreach (var label in labels)
        {
            log.LogInformation("Label: [{labelId}] {labelName} : {labelDescription} - Color: {labelColor}", label.Id, label.Name, label.Description, label.Color);
        }
        break;

    case "delabel":
        result = await mip.RemoveLabelAsync(
            config["input"]!, config["output"]!, 
            config.GetValue("MIP:Justification", "Label removed programmatically")!);

        if (!result)
        {
            log.LogError("Failed to remove label from {input}", config["input"]);
        }

        break;

    case "label":
        var lbl = mip.GetLabels().FirstOrDefault(x => x.Id == config["label"] || x.Name == config["label"] || x.Description == config["label"]);
        if (lbl == null)
        {
            log.LogError("Unable to file label {label}", config["label"]);
        }
        else
        {
            await mip.SetLabelAsync(
                   config["input"]!, config["output"]!, 
                   lbl, config["MIP:Justification"]!);
        }
        break;

    case "inspect":
        input = config["input"]!;
        if (input.EndsWith(".eml", StringComparison.InvariantCultureIgnoreCase))
        {
            var eml = MsgReader.Mime.Message.Load(new FileInfo(input));
            var wrappedMsg = Path.ChangeExtension(input, ".wrapped.msg");
            if (eml.Attachments.Count == 0 || !eml.Attachments[0].FileName.EndsWith(".rpmsg", StringComparison.InvariantCultureIgnoreCase))
            {
                log.LogWarning("Input file {input} is not an encrypted message!!", input);
                Environment.Exit(1);
            }

            using (var wrappedMsgFs = File.Create(wrappedMsg))
            {
                MSGUtils.EmplaceAttachmentInMsgFile(config["msgTemplate"]!, eml.Attachments[0].Body, wrappedMsgFs);
            }
            input = wrappedMsg;
        }
        var inspectResult = await mip.InspectMSGAsync(input);
        log.LogInformation("InspectFileAsync: body type = {bodyType}, attachments count = {attCount}", inspectResult?.BodyType, inspectResult?.Attachments?.Count);
        Console.WriteLine(inspectResult?.Body);
        break;
}

log.LogInformation("END");

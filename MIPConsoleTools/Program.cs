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
using var logScope = log.BeginScope("[mtid={tid,5}]", new ManagedThreadIdGenerator());

log.LogInformation("ClientId = {clientId}", config["MIP:ClientId"]);

MIPMain mip = new (
    miplog,
    config.GetValue<Microsoft.InformationProtection.LogLevel>("MIP:LogLevel"),
    config["MIP:TenantId"]!, config["MIP:ClientId"]!, config["MIP:AppName"]!, config["MIP:AppVersion"]!,
    config["MIP:Username"]!, config["MIP:ClientSecret"]!, delegatedUser: config["MIP:DelegatedUser"] );

switch (config["action"])
{
    case "decrypt":
        var input = config["input"]!;
        if (input.EndsWith(".eml", StringComparison.InvariantCultureIgnoreCase))
        {
            var eml = MsgReader.Mime.Message.Load(new FileInfo(input));
            var wrappedMsg = Path.ChangeExtension(input, ".wrapped.msg");
            using (var wrappedMsgFs = File.Create(wrappedMsg))
            {
                MSGUtils.EmplaceAttachmentInMsgFile(config["msgTemplate"]!, eml.Attachments[0].Body, wrappedMsgFs);
            }
            input = wrappedMsg;
        }
        using (var fs = File.Create(config["output"]!))
        {
            await mip.DecryptFileAsync(input, fs);
        }
        break;

    case "delabel":
        await mip.RemoveLabelAsync(
            config["input"]!, config["output"]!, 
            config.GetValue("MIP:Justification", "Label removed programmatically")!);
        break;

    case "inspect":
        var result = await mip.InspectMSGAsync(config["input"]!);
        log.LogInformation("InspectFileAsync: body type = {bodyType}, attachments count = {attCount}", result?.BodyType, result?.Attachments?.Count);
        Console.WriteLine(result?.Body);
        break;
}

log.LogInformation("END");

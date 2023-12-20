using OpenMcdf;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

namespace MIPConsoleTools.CDF
{
    public static class CDFUtils
    {
        public record CDFInfo(string TenantId, string Owner, string? LabelId, string? LabelName, string? LabelDescription, XmlDocument PrimaryXml);

        public static CDFInfo GetInformationProtectionData(string fileName)
        {
            using var fs = File.OpenRead(fileName);
            using var cf = new CompoundFile(fs, CFSUpdateMode.ReadOnly, CFSConfiguration.Default);

            var drmDataSpace = cf.RootStorage.GetStorage("\u0006DataSpaces");
            var transformInfo = drmDataSpace.GetStorage("TransformInfo");
            var drmTransform = transformInfo.GetStorage("\u0009DRMTransform");
            var primary = drmTransform.GetStream("\u0006Primary");

            var data = primary.GetData();

            var classIDLength = BitConverter.ToInt32(data, 8);
            var featureIdentifierLength = BitConverter.ToInt32(data, 12 + classIDLength);
            var rightsLabelLength = BitConverter.ToInt32(data, 34 + classIDLength + featureIdentifierLength);

            var xml = Encoding.UTF8.GetString(data.Skip(38 + classIDLength + featureIdentifierLength).ToArray()).TrimEnd('\0');

            xml = Regex.Replace(xml, "^(<\\?xml .*\\?>)", "$1<root>") + "</root>";

            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var tenantId = doc.SelectSingleNode("//ADDRESS[@type='home_tenantId']")?.InnerText!;
            var owner = doc.SelectSingleNode("//OWNER/OBJECT/NAME")?.InnerText!;
            var labelId = doc.SelectSingleNode("//BODY/DESCRIPTOR/OBJECT/ID")?.InnerText;
            var labelNameElements = (doc.SelectSingleNode("//BODY/DESCRIPTOR/OBJECT/NAME")?.InnerText ?? "").TrimEnd(';').Split(':')
                .Where(x => x.Contains(' '))
                .ToDictionary(x => x[..x.IndexOf(' ')], y => y[(y.IndexOf(' ') + 1)..]);
            labelNameElements.TryGetValue("NAME", out var labelName);
            labelNameElements.TryGetValue("DESCRIPTION", out var labelDescription);

            return new CDFInfo(tenantId, owner, labelId, labelName, labelDescription, doc);
        }
    }
}

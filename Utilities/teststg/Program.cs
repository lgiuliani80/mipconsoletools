using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

var iidIStorage = new Guid("0000000b-0000-0000-C000-000000000046");
var filestorage = CompondDocumentUtils.StgOpenStorageEx(
    args[0], CompondDocumentUtils.STGM_READWRITE | CompondDocumentUtils.STGM_SHARE_EXCLUSIVE, 0, 0, 
    IntPtr.Zero, IntPtr.Zero, ref iidIStorage);

var drmDataSpace = filestorage.OpenStorage("\u0006DataSpaces", null, CompondDocumentUtils.STGM_READ | CompondDocumentUtils.STGM_SHARE_EXCLUSIVE, null, 0);
var transformInfo = drmDataSpace.OpenStorage("TransformInfo", null, CompondDocumentUtils.STGM_READ | CompondDocumentUtils.STGM_SHARE_EXCLUSIVE, null, 0);
var drmTransform = transformInfo.OpenStorage("\u0009DRMTransform", null, CompondDocumentUtils.STGM_READ | CompondDocumentUtils.STGM_SHARE_EXCLUSIVE, null, 0);
var primary = drmTransform.OpenStream("\u0006Primary", IntPtr.Zero, CompondDocumentUtils.STGM_READ | CompondDocumentUtils.STGM_SHARE_EXCLUSIVE, 0);

primary.Stat(out var stat, 0);
var data = new byte[stat.cbSize];
primary.Read(data, (uint)stat.cbSize);

var classIDLength = BitConverter.ToInt32(data, 8);
var featureIdentifierLength = BitConverter.ToInt32(data, 12 + classIDLength);
var rightsLabelLength = BitConverter.ToInt32(data, 34 + classIDLength + featureIdentifierLength);

var xml = Encoding.UTF8.GetString(data.Skip(38 + classIDLength + featureIdentifierLength).ToArray()).TrimEnd('\0');

xml = Regex.Replace(xml, "^(<\\?xml .*\\?>)", "$1<root>") + "</root>";

var doc = new XmlDocument();
doc.LoadXml(xml);
var tenantId = doc.SelectSingleNode("//ADDRESS[@type='home_tenantId']")?.InnerText;
var owner = doc.SelectSingleNode("//OWNER/OBJECT/NAME")?.InnerText;

Console.WriteLine($"Tenant ID: {tenantId}");
Console.WriteLine($"Owner    : {owner}");

if (args.Length >= 2) 
{
    var xmlWriterSettings = new XmlWriterSettings
    {
        Indent = true,
        IndentChars = "  ",
        NewLineChars = "\r\n",
        NewLineHandling = NewLineHandling.Replace,
        Encoding = Encoding.UTF8
    };

    using (var xw = XmlWriter.Create(args[1], xmlWriterSettings))
    {
        doc.Save(xw);
    }
}

static class CompondDocumentUtils 
{
    public const uint STGM_READ              = 0x00000000;
    public const uint STGM_WRITE             = 0x00000001;
    public const uint STGM_READWRITE         = 0x00000002;
    public const uint STGM_SHARE_DENY_NONE   = 0x00000040;
    public const uint STGM_SHARE_DENY_READ   = 0x00000030;
    public const uint STGM_SHARE_DENY_WRITE  = 0x00000020;
    public const uint STGM_SHARE_EXCLUSIVE   = 0x00000010;

    [DllImport("ole32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
    public static extern IStorage StgOpenStorageEx(
        string pwcsName,
        uint grfMode,
        uint stgfmt,
        uint grfAttrs,
        IntPtr pStgOptions,
        IntPtr pSecurityDescriptor,
        ref Guid riid
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct STATSTG
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwcsName;
        public uint type;
        public ulong cbSize;
        public ulong mtime;
        public ulong ctime;
        public ulong atime;
        public uint grfMode;
        public uint grfLocksSupported;
        public uint clsid;
        public uint grfStateBits;
        public uint reserved;
    }

    [Guid("0000000d-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IEnumSTATSTG
    {
        uint Next( 
            uint celt,
            out STATSTG rgelt,
            out uint pceltFetched);
        
        void Skip(uint celt);
        
        void Reset();
        
        IEnumSTATSTG Clone();
    }

    [Guid("0000000b-0000-0000-C000-000000000046"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStorage 
    {
        IStream CreateStream(
            string pwcsName, 
            uint grfMode, 
            uint reserved1, 
            uint reserved2);
        
        IStream OpenStream( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            IntPtr reserved1,
            uint grfMode,
            uint reserved2);
        
        IStorage CreateStorage( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            uint grfMode,
            uint reserved1,
            uint reserved2);
        
        IStorage OpenStorage( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            IStorage? pstgPriority,
            uint grfMode,
            [MarshalAs(UnmanagedType.LPWStr)] string? snbExclude,
            uint reserved);
        
        void CopyTo( 
            uint ciidExclude,
            ref Guid rgiidExclude,
            [MarshalAs(UnmanagedType.LPWStr)] string? snbExclude,
            IStorage pstgDest);
        
        void MoveElementTo( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            IStorage pstgDest,
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsNewName,
            uint grfFlags);
        
        void Commit( 
            uint grfCommitFlags);
        
        void Revert();
        
        IEnumSTATSTG EnumElements( 
            uint reserved1,
            IntPtr reserved2,
            uint reserved3);
        
        void DestroyElement( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName);
        
        void RenameElement( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsOldName,
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsNewName);
        
        void SetElementTimes( 
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            ref ulong pctime,
            ref ulong patime,
            ref ulong pmtime);
        
        void SetClass( 
            ref Guid clsid);
        
        void SetStateBits( 
            uint grfStateBits,
            uint grfMask);
        
        void Stat( 
            out STATSTG pstatstg,
            uint grfStatFlag);
    }

    [Guid("0000000c-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStream
    {
        uint Read( 
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv,
            uint cb);
        
        uint Write( 
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv,
            uint cb);
        
        ulong Seek( 
            ulong dlibMove,
            uint dwOrigin);
        
        void SetSize( 
            ulong libNewSize);
        
        void CopyTo( 
            IStream pstm,
            ulong cb,
            out ulong pcbRead,
            out ulong pcbWritten);
        
        void Commit( 
            uint grfCommitFlags);
        
        void Revert();
        
        void LockRegion( 
            ulong libOffset,
            ulong cb,
            uint dwLockType);
        
        void UnlockRegion( 
            ulong libOffset,
            ulong cb,
            uint dwLockType);
        
        void Stat( 
            out STATSTG pstatstg,
            uint grfStatFlag);
        
        IStream Clone();
    }

}
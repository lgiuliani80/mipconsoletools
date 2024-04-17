param(
	[Parameter(Mandatory = $true)][string]$InputFile,
	[Parameter(Mandatory = $false)][string]$OutputCompoundDocumentFile,
	[Parameter(Mandatory = $true)][string]$OutputPrimaryXMLFile
)

$ErrorActionPreference = 'Break'

$IsTemporary = $false

### Adding CompoundDocumentUtils ###
if (-not [Type]::GetType("CompoundDocumentUtils")) {
	Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class CDStorage : IDisposable
{
	CompoundDocumentUtils.IStorage stg;

	internal CDStorage(CompoundDocumentUtils.IStorage st) 
	{
		stg = st;
	}

	public CDStorage(string pwcsName,
		uint grfMode,
		uint stgfmt,
		uint grfAttrs,
		IntPtr pStgOptions,
		IntPtr pSecurityDescriptor,
		ref Guid riid) 
	{
		stg = CompoundDocumentUtils.StgOpenStorageEx(pwcsName, grfMode, stgfmt, grfAttrs, pStgOptions, pSecurityDescriptor, ref riid);
	}

	public CDStorage OpenStorage(string pwcsName)
	{
		var isst = stg.OpenStorage(pwcsName, null, CompoundDocumentUtils.STGM_READ | CompoundDocumentUtils.STGM_SHARE_EXCLUSIVE, null, 0);
		return new CDStorage(isst);
	}

	public CDStream OpenStream(string pwcsName)
	{
		var iss = stg.OpenStream(pwcsName, IntPtr.Zero, CompoundDocumentUtils.STGM_READ | CompoundDocumentUtils.STGM_SHARE_EXCLUSIVE, 0);
		return new CDStream(iss);
	}

	public void Dispose()
	{
		if (stg != null) {
			Marshal.ReleaseComObject(stg);
			stg = null;
		}
	}
}

public class CDStream : IDisposable
{
	CompoundDocumentUtils.IStream stm;

	internal CDStream(CompoundDocumentUtils.IStream st) 
	{
		stm = st;
	}

	public byte[] ReadAll() 
	{
		stm.Stat(out var stat, 0);
		byte[] data = new byte[stat.cbSize];
		stm.Read(data, (uint)stat.cbSize);
		return data;
	}

	public void Dispose()
	{
		if (stm != null) {
			Marshal.ReleaseComObject(stm);
			stm = null;
		}
	}
}

public static class CompoundDocumentUtils 
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
            IStorage pstgPriority,
            uint grfMode,
            [MarshalAs(UnmanagedType.LPWStr)] string snbExclude,
            uint reserved);
        
        void CopyTo( 
            uint ciidExclude,
            ref Guid rgiidExclude,
            [MarshalAs(UnmanagedType.LPWStr)] string snbExclude,
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
'@
}

if ([IO.Path]::GetExtension($InputFile).ToLower() -eq ".rpmsg") {
    if ([string]::IsNullOrWhiteSpace($OutputCompoundDocumentFile)) {
        $OutputCompoundDocumentFile = [IO.Path]::GetTempFileName()
        $IsTemporary = $true
    }

    ### Decompressing .rpmsg file ###
    $rpmsg_signature = [byte[]] @( 0x76, 0xe8, 0x04, 0x60, 0xc4, 0x11, 0xe3, 0x86 )

    Write-Verbose "- Opening files ..."

    try {
        $resolvedInput = Resolve-Path $InputFile
        $fin = [System.IO.File]::OpenRead($resolvedInput)
        $msout = New-Object System.IO.MemoryStream

        Write-Verbose "- Checking signature ..."
        $signature = New-Object byte[] 8
        $fin.Read($signature, 0, 8) | Out-Null
        if (-not [Linq.Enumerable]::SequenceEqual($signature, $rpmsg_signature)) {
            throw "Invalid signature"
        }
        Write-Verbose "- Copying data ..."

        $total_uncompressed = 0
        $total_compressed = 0

        $buffer = New-Object byte[] 8192

        $nchunk = 1

        while (-not $fin.EndOfStream) {
            $magic = New-Object byte[] 4
            $c = $fin.Read($magic, 0, 4)
            if ($fin.EndOfStream -or ($c -eq 0)) { break }

            if (($c -ne 4) -or -not [Linq.Enumerable]::SequenceEqual($magic, [byte[]]@(0xa0, 0x0f, 0, 0))) {
                throw "Invalid magic at offset $($fin.Position)"
            }

            $tmpInt4 = New-Object byte[] 4

            $c = $fin.Read($tmpInt4, 0, 4)
            if ($c -ne 4) {
                throw "Unable to read uncompressed length at offset $($fin.Position)"
            }
            $uncompressed_len = [BitConverter]::ToUInt32($tmpInt4, 0)

            $c = $fin.Read($tmpInt4, 0, 4);
            if ($c -ne 4) {
                throw "Unable to read compressed length at offset $($fin.Position)"
            }
            $compressed_len = [BitConverter]::ToUInt32($tmpInt4, 0)

            $total_compressed += $compressed_len;
            $total_uncompressed += $uncompressed_len;

            Write-Verbose ("  * Reading chunk {0,4} : compressed = {1,10} , uncompressed = {2,10}" -f $nchunk, $compressed_len, $uncompressed_len)

            $nwritten = 0;
            $nread = 0;
            $toread = $compressed_len;

            while ( ($nwritten -lt $compressed_len) -and -not $fin.EndOfStream) {
                $nread = $fin.Read($buffer, 0, [Math]::Min($toread, $buffer.Length));
                $msout.Write($buffer, 0, $nread);
                $nwritten += $nread
                $toread -= $nread
            }

            $nchunk++
        }
        
        Write-Verbose ("  # Completed: total chunks = {0}, total compressed len = {1}, total uncompressed len = {2}" -f ($nchunk - 1), $total_compressed, $total_uncompressed)

        $msout.Position = 0
        $zlib = New-Object System.IO.Compression.ZLibStream($msout, [System.IO.Compression.CompressionMode]::Decompress)

        $fout = [System.IO.File]::OpenWrite($OutputCompoundDocumentFile)
        $zlib.CopyTo($fout)

    } finally {
        if ($fin) { $fin.Close() }
        if ($fout) { $fout.Close() }
        if ($msout) { $msout.Close() }
        if ($zlib) { $zlib.Close() }
    }
} else {
    $OutputCompoundDocumentFile = $InputFile
}

### Extracting Primary.xml ###

$iidIStorage = [Guid]"0000000b-0000-0000-C000-000000000046"
$filestorage = [CDStorage]::new($OutputCompoundDocumentFile, `
	[CompoundDocumentUtils]::STGM_READWRITE -bor [CompoundDocumentUtils]::STGM_SHARE_EXCLUSIVE, `
	0, 0, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $iidIStorage)

$drmDataSpace = $filestorage.OpenStorage("`u{0006}DataSpaces")
$transformInfo = $drmDataSpace.OpenStorage("TransformInfo")
$drmTransform = $transformInfo.OpenStorage("`u{0009}DRMTransform")
$primary = $drmTransform.OpenStream("`u{0006}Primary")

$data = $primary.ReadAll()

$classIDLength = [BitConverter]::ToInt32($data, 8);
$featureIdentifierLength = [BitConverter]::ToInt32($data, 12 + $classIDLength);
$rightsLabelLength = [BitConverter]::ToInt32($data, 34 + $classIDLength + $featureIdentifierLength);

$startIdx = 38 + $classIDLength + $featureIdentifierLength
$xml = [Text.Encoding]::UTF8.GetString($data, $startIdx, $data.Length - $startIdx).TrimEnd("`0");

$xml = ($xml -replace '^(<\?xml .*\?>)', '$1<root>') + "</root>";

$doc = [xml]$xml;
$tenantId = $doc.SelectSingleNode("//ADDRESS[@type='home_tenantId']").InnerText;
$owner = $doc.SelectSingleNode("//OWNER/OBJECT/NAME").InnerText;

$resolvedOutput = $OutputPrimaryXMLFile
$doc.Save($resolvedOutput)

$primary.Dispose();
$drmTransform.Dispose();
$transformInfo.Dispose();
$drmDataSpace.Dispose();
$filestorage.Dispose();

if ($IsTemporary) {
	Remove-Item $OutputCompoundDocumentFile
}

[pscustomobject]@{
	TenantId = $tenantId
	Owner = $owner
}
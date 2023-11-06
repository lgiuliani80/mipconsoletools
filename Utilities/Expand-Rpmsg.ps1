param(
	[Parameter(Mandatory = $true)][string]$InputRpmsgFile,
	[Parameter(Mandatory = $true)][string]$OutputCompoundDocumentFile
)

$rpmsg_signature = [byte[]] @( 0x76, 0xe8, 0x04, 0x60, 0xc4, 0x11, 0xe3, 0x86 )

Write-Host "- Opening files ..."

try {
	$fin = [System.IO.File]::OpenRead($InputRpmsgFile)
	$msout = New-Object System.IO.MemoryStream

	Write-Host "- Checking signature ..."
	$signature = New-Object byte[] 8
	$fin.Read($signature, 0, 8) | Out-Null
	if (-not [Linq.Enumerable]::SequenceEqual($signature, $rpmsg_signature)) {
		throw "Invalid signature"
	}
	Write-Host "- Copying data ..."

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

		Write-Host ("  * Reading chunk {0,4} : compressed = {1,10} , uncompressed = {2,10}" -f $nchunk, $compressed_len, $uncompressed_len)

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
	
	Write-Host ("  # Completed: total chunks = {0}, total compressed len = {1}, total uncompressed len = {2}" -f ($nchunk - 1), $total_compressed, $total_uncompressed)

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

$fi = New-Object System.IO.FileInfo($OutputCompoundDocumentFile)
Write-Host "- Done: $($fi.Length) bytes written to $($fi.FullName)"
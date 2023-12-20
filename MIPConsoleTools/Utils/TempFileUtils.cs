using System;

namespace MIPConsoleTools.Utils
{
    public class FileNameWrapper : IDisposable
    {
        public string FileName { get; private set; }
        public bool DeleteAtDispose { get; private set; }

        public FileNameWrapper(string fileName, bool deleteAtDispose)
        {
            FileName = fileName;
            DeleteAtDispose = deleteAtDispose;
        }
        public string? Label { get; set; }
        public void Dispose()
        {
            DoDispose();
            GC.SuppressFinalize(this);
        }
        private void DoDispose()
        {
            if (DeleteAtDispose)
            {
                try { FileUtils.Delete(FileName); } catch { }
            }
        }

        public static implicit operator string(FileNameWrapper w) => w.FileName;
        public override string ToString() => FileName;

        public void ReplaceWith(FileNameWrapper other)
        {
            DoDispose();
            FileName = other.FileName;
            DeleteAtDispose = other.DeleteAtDispose;
            other.DeleteAtDispose = false;
        }
    }
    public class TempFileWrapper : FileNameWrapper
    {
        public TempFileWrapper(string OriginalFileName)
            : base(Path.Combine(Path.GetTempPath(), $"att-{Guid.NewGuid()}-{OriginalFileName}"), true) 
        {}
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
        public override string ToString() => DirectoryName;
    }

    public class DecryptResult
        : FileNameWrapper
    {
        public bool WasDecrypted { get; set; }
        public DecryptResult(string DecryptedFileName, bool WasDecrypted) : base(DecryptedFileName, WasDecrypted) 
        { 
            this.WasDecrypted = WasDecrypted;
        }
    }
}

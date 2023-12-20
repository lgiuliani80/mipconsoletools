using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MIPConsoleTools.Utils
{
    public static class FileUtils
    {
        private static readonly Random random = new();

        public static ILogger? Logger { get; set; }

        public static void Delete(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return;

            try
            {
                File.Delete(fileName);
                Logger?.LogDebug("Deleted {fileName}", fileName);
            }
            catch (IOException ioe)
            {
                // TODO: improve to consider only the case when the file is in use
                var waitTimeS = random.NextDouble() * 3 + 1;

                Logger?.LogWarning(ioe, "Exception while deleting {fileName}. Will try to delete it again in {waitTimeS} seconds.", fileName, waitTimeS);
                Task.Delay(TimeSpan.FromSeconds(waitTimeS)).ContinueWith(t => Delete(fileName));
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, "Exception while deleting {fileName}. With this exception no more retries will be attempted.", fileName);
            }
        }
    }
}

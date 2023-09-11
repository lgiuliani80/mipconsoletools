using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;

namespace MIPConsoleTools
{
    public class AuthDelegateImplementation : IAuthDelegate
    {
        public const string CERTIFICATE_PREFIX = "thumbprint:";

        private readonly ILogger _logger;
        private readonly ApplicationInfo _appInfo;
        private readonly string _tenantId, _clientSecretOrCertificate;
        
        public AuthDelegateImplementation(ILogger logger, ApplicationInfo appInfo, string tenantId, string clientSecretOrCertificate)
        {
            _logger = logger;
            _appInfo = appInfo;
            _tenantId = tenantId;
            _clientSecretOrCertificate = clientSecretOrCertificate;
        }

        public string AcquireToken(Identity identity, string authority, string resource, string claims)
        {
            _logger.LogInformation("AcquireToken: Identity={identityName} ({identityEmail}); Authority={authority}; resource={resource}; claims={claims}",
                identity.Name, identity.Email, authority, resource, claims);

            var authorityUri = new Uri(authority);
            authority = $"https://{authorityUri.Host}/{_tenantId}";
            
            var scopes = new string[] { resource[^1] == '/' ? $"{resource}.default" : $"{resource}/.default" };

            var cclientBuilder = ConfidentialClientApplicationBuilder.Create(_appInfo.ApplicationId)
#if USE_WINHTTP
                .WithHttpClientFactory(new WinHttpMsalHttpClientFactory())
#endif
                .WithAuthority(authority);
            
            if (_clientSecretOrCertificate.StartsWith(CERTIFICATE_PREFIX))
            {
                var st = new X509Store(StoreName.My);
                var cert = st.Certificates.Find(X509FindType.FindByThumbprint, _clientSecretOrCertificate[CERTIFICATE_PREFIX.Length..], false).FirstOrDefault();

                if (cert == null)
                {
                    st = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    cert = st.Certificates.Find(X509FindType.FindByThumbprint, _clientSecretOrCertificate[CERTIFICATE_PREFIX.Length..], false).First();
                }

                cclientBuilder = cclientBuilder.WithCertificate(cert);
            }
            else 
            {
                cclientBuilder = cclientBuilder.WithClientSecret(_clientSecretOrCertificate);
            }

            var cclient = cclientBuilder.Build();

            var result = cclient.AcquireTokenForClient(scopes)
                .ExecuteAsync()
                .ConfigureAwait(false)
                .GetAwaiter().GetResult();

            return result.AccessToken;
        }
    }

#if USE_WINHTTP
    internal class WinHttpMsalHttpClientFactory : IMsalHttpClientFactory
    {
        public HttpClient GetHttpClient()
        {
            if (OperatingSystem.IsWindows())
            {
                return new HttpClient(handler: new WinHttpHandler(), true);
            }
            else
            {
                return new HttpClient();
            }
        }
    }
#endif
}

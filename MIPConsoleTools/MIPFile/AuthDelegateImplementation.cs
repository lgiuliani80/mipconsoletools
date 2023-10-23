using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using Microsoft.Identity.Client.Platforms.Features.DesktopOs;
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
        private readonly bool _isInteractive;
        
        public AuthDelegateImplementation(ILogger logger, ApplicationInfo appInfo, string tenantId, string clientSecretOrCertificate, bool isInteractive)
        {
            _logger = logger;
            _appInfo = appInfo;
            _tenantId = tenantId;
            _clientSecretOrCertificate = clientSecretOrCertificate;
            _isInteractive = isInteractive;
        }

        public string AcquireToken(Identity identity, string authority, string resource, string claims)
        {
            _logger.LogInformation("AcquireToken: Identity={identityName} ({identityEmail}); Authority={authority}; resource={resource}; claims={claims}",
                identity.Name, identity.Email, authority, resource, claims);

            var authorityUri = new Uri(authority);
            var isForeignTenant = authorityUri.PathAndQuery.Split('/')[1] != _tenantId && authorityUri.PathAndQuery.Split('/')[1] != "common";

            if (_isInteractive || isForeignTenant)
            {
                // THIS BRANCH OF THE CODE IS *NOT* OF INTEREST FOR LLOYDS - PLEASE DO NOT INCLUDE IN YOUR CODE
                var pclientBuilder = PublicClientApplicationBuilder.Create("c00e9d32-3c8d-4a7d-832b-029040e7db99" /*_appInfo.ApplicationId*/);
                pclientBuilder.WithAuthority(authority).WithRedirectUri("com.microsoft.azip://authorize");

                var scopes = new string[] { resource[^1] == '/' ? $"{resource}.default" : $"{resource}/.default", "offline_access" };

                var pclient = pclientBuilder.Build();

                var result = pclient.AcquireTokenInteractive(scopes)
                    .WithUseEmbeddedWebView(true)
                    .ExecuteAsync()
                    .ConfigureAwait(false)
                    .GetAwaiter().GetResult();

                // NOTE: ROPC seems not supported for Azure Rights Management Service, at least in multi-tenant environments.

                return result.AccessToken;
                // END OF NON-INTERESTING CODE
            }
            else
            {
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

/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
 
// From azure sdk sample
// https://azure.github.io/azure-sdk-for-java/com/microsoft/azure/keyvault/authentication/KeyVaultCredentials.html

package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.microsoft.aad.adal4j.*;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class AzureKeyVaultCredential extends KeyVaultCredentials
{
    private String applicationID;
    private String applicationSecret;
  
    public AzureKeyVaultCredential(String applicationID, String applicationSecret)
    {
        this.applicationID = applicationID;
        this.applicationSecret = applicationSecret;
    }

    @Override
    public String doAuthenticate(String authorization, String resource, String scope) {
        AuthenticationResult token = getAccessTokenFromClientCredentials(authorization, resource, applicationID, applicationSecret);
        return token.getAccessToken();
    }

    private static AuthenticationResult getAccessTokenFromClientCredentials(String authorization, String resource, String clientId, String clientKey) {
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authorization, false, service);
            ClientCredential credentials = new ClientCredential(clientId, clientKey);
            Future<AuthenticationResult> future = context.acquireToken(resource, credentials, null);
            result = future.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (service != null) {
                service.shutdown();
            }
        }

        if (result == null) {
            throw new RuntimeException("Authentication result was null");
        }
        return result;
    }
}
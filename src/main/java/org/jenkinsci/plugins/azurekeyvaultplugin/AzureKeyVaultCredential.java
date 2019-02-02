/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2017 Microsoft Corporation
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
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

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import hudson.util.Secret;
import org.apache.commons.lang3.StringUtils;

import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class AzureKeyVaultCredential extends KeyVaultCredentials {
    private String applicationID;
    private Secret applicationSecret;

    public AzureKeyVaultCredential() {

    }

    public AzureKeyVaultCredential(String applicationID, Secret applicationSecret) {
        this.applicationID = applicationID;
        this.applicationSecret = applicationSecret;
    }

    public void setApplicationID(String applicationID) {
        this.applicationID = applicationID;
    }

    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = Secret.fromString(applicationSecret);
    }

    public void setApplicationSecret(Secret applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    public boolean isApplicationIDValid() {
        return !StringUtils.isEmpty(applicationID);
    }

    public boolean isApplicationSecretValid() {
        return AzureKeyVaultUtil.isNotEmpty(applicationSecret);
    }

    public boolean isValid() {
        return isApplicationIDValid() && isApplicationSecretValid();
    }

    @Override
    public String doAuthenticate(String authorization, String resource, String scope) {
        Objects.requireNonNull(applicationSecret, "Application secret is a required value");
        AuthenticationResult token = getAccessTokenFromClientCredentials(authorization, resource, applicationID, applicationSecret
                .getPlainText());
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
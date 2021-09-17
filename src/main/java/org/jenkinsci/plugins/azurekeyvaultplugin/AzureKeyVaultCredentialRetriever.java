package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.microsoft.azure.util.AzureBaseCredentials;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.azure.util.AzureImdsCredentials;
import hudson.model.Run;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import org.apache.commons.lang3.StringUtils;

import static java.lang.String.format;

public class AzureKeyVaultCredentialRetriever {
    private static final Logger LOGGER = Logger.getLogger(AzureKeyVaultStep.class.getName());

    @CheckForNull
    public static TokenCredential getCredentialById(String credentialID, Run<?, ?> build) {
        TokenCredential credential;
        AzureBaseCredentials cred = CredentialsProvider.findCredentialById(credentialID, AzureBaseCredentials.class, build);

        if (cred == null) {
            throw new AzureKeyVaultException(String.format("Credential: %s was not found", credentialID));
        }

        if (cred instanceof AzureCredentials) {
            LOGGER.log(Level.FINE, format("Fetched %s as AzureCredentials", credentialID));
            CredentialsProvider.track(build, cred);
            AzureCredentials azureCredentials = (AzureCredentials) cred;
            credential = new ClientSecretCredentialBuilder()
                    .clientId(azureCredentials.getClientId())
                    .clientSecret(azureCredentials.getPlainClientSecret())
                    .httpClient(HttpClientRetriever.get())
                    .tenantId(azureCredentials.getTenant())
                    .build();
        } else if (cred instanceof AzureImdsCredentials) {
            credential = new ManagedIdentityCredentialBuilder().build();
        } else {
            throw new AzureKeyVaultException("Could not determine the type for Secret id "
                    + credentialID +
                    " only 'Azure Service Principal' and 'Azure Managed Identity' are supported");
        }

        return credential;
    }

    public static TokenCredential getCredentialById(String credentialID) {
        if (StringUtils.isEmpty(credentialID)) {
            return null;
        }
        SystemCredentialsProvider systemCredentialsProvider = SystemCredentialsProvider.getInstance();
        List<AzureImdsCredentials> azureImdsCredentials =
                DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                        AzureImdsCredentials.class,
                        Collections.emptyList(),
                        CredentialsMatchers.withId(credentialID));

        if (!azureImdsCredentials.isEmpty()) {
            return new ManagedIdentityCredentialBuilder().build();
        }

        List<AzureCredentials> azureCredentials =
                DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                        AzureCredentials.class,
                        Collections.emptyList(),
                        CredentialsMatchers.withId(credentialID));

        ClientSecretCredential credential = null;
        if (!azureCredentials.isEmpty()) {
            LOGGER.log(Level.FINE, format("Fetched %s as AzureCredentials", credentialID));
            AzureCredentials azureCredential = azureCredentials.get(0);

            credential = new ClientSecretCredentialBuilder()
                    .clientId(azureCredential.getClientId())
                    .clientSecret(azureCredential.getPlainClientSecret())
                    .httpClient(HttpClientRetriever.get())
                    .tenantId(azureCredential.getTenant())
                    .build();
        }

        if (credential == null) {
            throw new AzureKeyVaultException(String.format("Credential: %s was not found for supported credentials " +
                    "type.", credentialID));
        }
        return credential;
    }

    static KeyVaultSecret getSecretBundle(SecretClient client, AzureKeyVaultSecret secret) {
        try {
            if (StringUtils.isEmpty(secret.getVersion())) {
                return client.getSecret(secret.getName());
            }
            return client.getSecret(secret.getName(), secret.getVersion());
        } catch (Exception e) {
            throw new AzureKeyVaultException(
                    format(
                            "Failed to retrieve secret %s from vault %s, error message: %s",
                            secret.getName(),
                            client.getVaultUrl(),
                            e.getMessage()
                    ), e);
        }
    }

}

package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.azure.util.AzureImdsCredentials;
import hudson.model.Run;
import hudson.util.Secret;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.String.format;

public class AzureKeyVaultCredentialRetriever {
    private static final Logger LOGGER = Logger.getLogger(AzureKeyVaultStep.class.getName());


    public static KeyVaultCredentials getCredentialById(String credentialID, Run<?, ?> build) {
        AzureKeyVaultCredential credential;
        IdCredentials cred = CredentialsProvider.findCredentialById(credentialID, IdCredentials.class, build);

        if (cred == null) {
            throw new AzureKeyVaultException(String.format("Credential: %s was not found", credentialID));
        }

        if (cred instanceof StandardUsernamePasswordCredentials) {
            // Username/Password Object
            LOGGER.log(Level.FINE, format("Fetched %s as StandardUsernamePasswordCredentials", credentialID));
            CredentialsProvider.track(build, cred);
            StandardUsernamePasswordCredentials usernamePasswordCredentials = (StandardUsernamePasswordCredentials) cred;
            credential = new AzureKeyVaultCredential(
                    usernamePasswordCredentials.getUsername(),
                    usernamePasswordCredentials.getPassword()
            );

        } else if (cred instanceof AzureCredentials) {
            LOGGER.log(Level.FINE, format("Fetched %s as AzureCredentials", credentialID));
            CredentialsProvider.track(build, cred);
            AzureCredentials azureCredentials = (AzureCredentials) cred;
            credential = new AzureKeyVaultCredential(
                    azureCredentials.getClientId(),
                    Secret.fromString(azureCredentials.getPlainClientSecret())
            );
        } else if (cred instanceof AzureImdsCredentials) {
            return new AzureKeyVaultImdsCredential();
        } else {
            throw new AzureKeyVaultException("Could not determine the type for Secret id "
                    + credentialID +
                    " only 'Username/Password', and 'Microsoft Azure Service Principal' are supported");
        }

        if (!credential.isValid()) {
            throw new AzureKeyVaultException("No valid credentials were found for accessing KeyVault");
        }

        return credential;
    }

    public static KeyVaultCredentials getCredentialById(String credentialID) {
        SystemCredentialsProvider systemCredentialsProvider = SystemCredentialsProvider.getInstance();
        List<AzureImdsCredentials> azureImdsCredentials =
                DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                        AzureImdsCredentials.class,
                        Collections.emptyList(),
                        CredentialsMatchers.withId(credentialID));

        if (!azureImdsCredentials.isEmpty()) {
            return new AzureKeyVaultImdsCredential();
        }

        AzureKeyVaultCredential credential = null;
        List<StandardUsernamePasswordCredentials> usernamePasswordCredentials =
                DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                        StandardUsernamePasswordCredentials.class,
                        Collections.emptyList(),
                        CredentialsMatchers.withId(credentialID));
        if (!usernamePasswordCredentials.isEmpty()) {
            LOGGER.log(Level.FINE, format("Fetched %s as StandardUsernamePasswordCredentials", credentialID));
            StandardUsernamePasswordCredentials usernamePasswordCredential = usernamePasswordCredentials.get(0);
            credential = new AzureKeyVaultCredential(
                    usernamePasswordCredential.getUsername(),
                    usernamePasswordCredential.getPassword()
            );
        }

        List<AzureCredentials> azureCredentials =
                DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                        AzureCredentials.class,
                        Collections.emptyList(),
                        CredentialsMatchers.withId(credentialID));
        if (!azureCredentials.isEmpty()) {
            LOGGER.log(Level.FINE, format("Fetched %s as AzureCredentials", credentialID));
            AzureCredentials azureCredential = azureCredentials.get(0);
            credential = new AzureKeyVaultCredential(
                    azureCredential.getClientId(),
                    Secret.fromString(azureCredential.getPlainClientSecret())
            );
        }

        if (credential == null) {
            throw new AzureKeyVaultException(String.format("Credential: %s was not found for supported credentials " +
                    "type.", credentialID));
        }
        if (!credential.isValid()) {
            throw new AzureKeyVaultException("No valid credentials were found for accessing KeyVault");
        }
        return credential;
    }
}

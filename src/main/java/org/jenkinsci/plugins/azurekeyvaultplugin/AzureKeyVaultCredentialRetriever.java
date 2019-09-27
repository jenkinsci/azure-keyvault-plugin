package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.microsoft.azure.util.AzureCredentials;
import hudson.model.Run;
import hudson.util.Secret;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.String.format;

public class AzureKeyVaultCredentialRetriever {
    private static final Logger LOGGER = Logger.getLogger(AzureKeyVaultStep.class.getName());


    public static AzureKeyVaultCredential getCredentialById(String credentialID, Run<?, ?> build) {
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
}

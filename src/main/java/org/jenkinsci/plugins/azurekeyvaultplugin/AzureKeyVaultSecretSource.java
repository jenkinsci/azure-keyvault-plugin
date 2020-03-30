package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.azure.util.AzureCredentials;
import hudson.Extension;
import io.jenkins.plugins.casc.SecretSource;
import java.util.Optional;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;

@Extension(optional = true)
public class AzureKeyVaultSecretSource extends SecretSource {

    private static final Logger LOGGER = Logger.getLogger(AzureKeyVaultSecretSource.class.getName());

    @Override
    public Optional<String> reveal(String secret) {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all().get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            LOGGER.info("No AzureKeyVault url found, skipping jcasc secret resolution");
            return Optional.empty();
        }

        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        TokenCredential keyVaultCredentials = AzureKeyVaultCredentialRetriever.getCredentialById(credentialID);
        if (keyVaultCredentials == null) {
            LOGGER.info("No AzureKeyVault credentials found, skipping jcasc secret resolution");
            return Optional.empty();
        }

        SecretClient client = AzureCredentials.createKeyVaultClient(keyVaultCredentials, azureKeyVaultGlobalConfiguration.getKeyVaultURL());

        KeyVaultSecret secretBundle = client.getSecret(secret);
        if (secretBundle != null) {
            return Optional.of(secretBundle.getValue());
        }

        LOGGER.info("Couldn't find secret: " + secret);
        return Optional.empty();
    }
}

package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.SecretBundle;
import hudson.Extension;
import io.jenkins.plugins.casc.SecretSource;
import java.io.IOException;
import java.util.Optional;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;

@Extension(optional = true)
public class AzureKeyVaultSecretSource extends SecretSource {

    private static final Logger LOGGER = Logger.getLogger(AzureKeyVaultSecretSource.class.getName());

    @Override
    public Optional<String> reveal(String secret) throws IOException {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all().get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            LOGGER.info("No AzureKeyVault url found, skipping jcasc secret resolution");
            return Optional.empty();
        }

        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        KeyVaultCredentials keyVaultCredentials = AzureKeyVaultCredentialRetriever.getCredentialById(credentialID);
        if (keyVaultCredentials == null) {
            LOGGER.info("No AzureKeyVault credentials found, skipping jcasc secret resolution");
            return Optional.empty();
        }

        KeyVaultClient client = new KeyVaultClient(keyVaultCredentials);
        String keyVaultURL = azureKeyVaultGlobalConfiguration.getKeyVaultURL();

        SecretBundle secretBundle = client.getSecret(keyVaultURL, secret);
        if (secretBundle != null) {
            return Optional.of(secretBundle.value());
        }

        LOGGER.info("Couldn't find secret: " + secret);
        return Optional.empty();
    }
}

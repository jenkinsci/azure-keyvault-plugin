package org.jenkinsci.plugins.azurekeyvaultplugin.credentials;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.BaseAzureKeyVaultCredentialsProvider;

/**
 * Descriptor for credential types backed by Azure Key Vault, only applicable to the Azure Key Vault providers.
 *
 * <p>Key Vault credentials are never created through a form, so unlike
 * {@code BaseStandardCredentials.BaseStandardCredentialsDescriptor} this does not provide ID validation.
 */
public abstract class AzureKeyVaultCredentialsDescriptor extends CredentialsDescriptor {

    @Override
    public boolean isApplicable(CredentialsProvider provider) {
        return BaseAzureKeyVaultCredentialsProvider.isAzureKeyVaultProvider(provider);
    }
}

package org.jenkinsci.plugins.azurekeyvaultplugin.credentials;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.BaseAzureKeyVaultCredentialsProvider;

/**
 * Descriptor for credential types backed by Azure Key Vault, only applicable to the Azure Key Vault providers.
 *
 * <p>Key Vault credentials are never created through a form, so unlike {@code BaseStandardCredentialsDescriptor}
 * this does not validate IDs.
 */
public abstract class AzureKeyVaultCredentialsDescriptor extends CredentialsDescriptor {

    /**
     * For a descriptor nested in its credential class.
     */
    protected AzureKeyVaultCredentialsDescriptor() {
    }

    protected AzureKeyVaultCredentialsDescriptor(Class<? extends Credentials> clazz) {
        super(clazz);
    }

    @Override
    public boolean isApplicable(CredentialsProvider provider) {
        return BaseAzureKeyVaultCredentialsProvider.isAzureKeyVaultProvider(provider);
    }
}

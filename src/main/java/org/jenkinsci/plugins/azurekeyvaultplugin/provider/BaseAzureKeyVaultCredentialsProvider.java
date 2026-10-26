package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.microsoft.azure.util.AzureBaseCredentials;

/**
 * Common parent of the providers that serve credentials from Azure Key Vault.
 * <p>
 * The Azure credential types in this plugin are only applicable to subclasses, see {@link #isAzureKeyVaultProvider(CredentialsProvider)}.
 */
public abstract class BaseAzureKeyVaultCredentialsProvider extends CredentialsProvider {

    public static boolean isAzureKeyVaultProvider(CredentialsProvider provider) {
        return provider instanceof BaseAzureKeyVaultCredentialsProvider;
    }

    /**
     * Key Vault can't hold the Azure credentials used to connect to it, and answering a lookup for them would
     * re-enter the provider while it is connecting to the vault.
     */
    protected static boolean isLookupSupported(Class<?> type) {
        return !AzureBaseCredentials.class.isAssignableFrom(type);
    }

    @Override
    public String getIconClassName() {
        return "icon-azure-key-vault-credentials-store";
    }
}

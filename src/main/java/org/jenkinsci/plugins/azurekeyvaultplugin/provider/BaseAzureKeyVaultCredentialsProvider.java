package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.microsoft.azure.util.AzureBaseCredentials;
import java.time.Duration;

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
     * Creates the builder for a provider's credentials cache, so all providers expire and refresh on the same schedule.
     * Metadata is refreshed every 10 minutes and dropped if it can't be refreshed for 2 hours.
     */
    protected static Caffeine<Object, Object> newCacheBuilder(long maximumSize) {
        return Caffeine.newBuilder()
                .maximumSize(maximumSize)
                .expireAfterWrite(Duration.ofMinutes(120))
                .refreshAfterWrite(Duration.ofMinutes(10));
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

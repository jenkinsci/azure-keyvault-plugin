package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.microsoft.azure.util.AzureBaseCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Common parent of the providers that serve credentials from Azure Key Vault.
 * <p>
 * The Azure credential types in this plugin are only applicable to subclasses, see {@link #isAzureKeyVaultProvider(CredentialsProvider)}.
 */
public abstract class BaseAzureKeyVaultCredentialsProvider extends CredentialsProvider {
    private static final Logger LOG = Logger.getLogger(BaseAzureKeyVaultCredentialsProvider.class.getName());

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
     * Wraps a fetch of a vault's credentials for the cache, which treats failures differently on the first load
     * and on a refresh.
     * <ul>
     *     <li>A failed first load caches no credentials until the next refresh, so lookups while the vault is
     *     unavailable don't each block on retrying it.</li>
     *     <li>A failed refresh is rethrown, so the cache keeps the last credentials loaded until they expire,
     *     rather than replacing them with none.</li>
     * </ul>
     */
    protected static <K> CacheLoader<K, Map<String, IdCredentials>> credentialsLoader(
            Function<K, Map<String, IdCredentials>> fetch) {
        return new CacheLoader<>() {
            @Override
            public Map<String, IdCredentials> load(@NonNull K key) {
                try {
                    return fetch.apply(key);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
                    return Collections.emptyMap();
                }
            }

            @Override
            public Map<String, IdCredentials> reload(@NonNull K key, @NonNull Map<String, IdCredentials> oldValue) {
                return fetch.apply(key);
            }
        };
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

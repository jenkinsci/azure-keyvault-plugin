package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.jenkins.keyvault.SecretClientCache;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.BaseAzureKeyVaultCredentialsProvider;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.KeyVaultCredentialsLoader;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.security.core.Authentication;


@Extension
public class AzureCredentialsProvider extends BaseAzureKeyVaultCredentialsProvider {
    private static final Logger LOG = Logger.getLogger(AzureCredentialsProvider.class.getName());

    private static final String CACHE_KEY = "key";

    /**
     * Reads the credentials from the vault, replaced in tests so they don't need a real Key Vault.
     */
    @VisibleForTesting
    @Restricted(NoExternalUse.class)
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "replaced in tests")
    public static BiFunction<String, String, Map<String, IdCredentials>> vaultLoader = (credentialID, keyVaultURL) ->
            KeyVaultCredentialsLoader.load(SecretClientCache.get(credentialID, keyVaultURL), keyVaultURL);

    private final AzureCredentialsStore store = new AzureCredentialsStore(this);

    private final LoadingCache<String, Map<String, IdCredentials>> cache = newCacheBuilder(1L)
            .build(credentialsLoader(key -> fetchCredentials()));

    public void refreshCredentials() {
        cache.invalidateAll();
    }

    @Override
    @CheckForNull
    public <C extends IdCredentials> C getCredentialByIdInItem(
            @NonNull String id,
            @NonNull Class<C> type,
            @NonNull Item item,
            @NonNull Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        return getCredentialsById(id, type, item instanceof Jenkins, authentication);
    }

    @Override
    @CheckForNull
    public <C extends IdCredentials> C getCredentialByIdInItemGroup(
            @NonNull String id,
            @NonNull Class<C> type,
            @NonNull ItemGroup<?> itemGroup,
            @NonNull Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        return getCredentialsById(id, type, itemGroup instanceof Jenkins, authentication);
    }

    private <C extends IdCredentials> C getCredentialsById(String id, Class<C> type, boolean contextIsJenkins, Authentication authentication) {
        if (ACL.SYSTEM2.equals(authentication) && isLookupSupported(type)) {
            try {
                final Map<String, IdCredentials> credentials = cache.get(CACHE_KEY);
                if (credentials == null) {
                    throw new IllegalStateException("Cache is not working");
                }

                IdCredentials credential = credentials.get(id);
                if (credential == null) {
                    return null;
                }
                if (credential.getId().equals(id)) {
                    if (CredentialsScope.SYSTEM == credential.getScope() && !(contextIsJenkins)) {
                        LOG.log(Level.FINEST, "getCredentialById {0} has SYSTEM scope but the context is not Jenkins. Ignoring credential", credential.getId());
                    } else if (type.isAssignableFrom(credential.getClass())) {
                        // cast to keep generics happy even though we are assignable
                        return type.cast(credential);
                    } else {
                        LOG.log(Level.FINEST, "getCredentialById {0} does not match", credential.getId());
                    }
                }
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
                return null;
            }
        }

        return null;
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentialsInItemGroup(
            @NonNull Class<C> aClass,
            @Nullable ItemGroup itemGroup,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        if (ACL.SYSTEM2.equals(authentication) && isLookupSupported(aClass)) {
            final ArrayList<C> list = new ArrayList<>();
            try {
                Map<String, IdCredentials> credentials = cache.get(CACHE_KEY);
                if (credentials == null) {
                    throw new IllegalStateException("Cache is not working");
                }

                for (IdCredentials credential : credentials.values()) {
                    if (aClass.isAssignableFrom(credential.getClass())) {
                        if (CredentialsScope.SYSTEM == credential.getScope() && !(itemGroup instanceof Jenkins)) {
                            LOG.log(Level.FINEST, "getCredentials {0} has SYSTEM scope but the context is not Jenkins. Ignoring credential", credential.getId());
                        } else if (aClass.isAssignableFrom(credential.getClass())) {
                            // cast to keep generics happy even though we are assignable
                            list.add(aClass.cast(credential));
                        } else {
                            LOG.log(Level.FINEST, "getCredentials {0} does not match", credential.getId());
                        }
                    }
                }
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
                return Collections.emptyList();
            }
            return list;
        }

        return Collections.emptyList();
    }

    @Override
    @NonNull
    public <C extends Credentials> List<C> getCredentialsInItem(
            @NonNull Class<C> type,
            @NonNull Item item,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        // scoping to Items is not supported so using null to not expose SYSTEM credentials to Items.
        Objects.requireNonNull(item);
        return getCredentialsInItemGroup(type, null, authentication, domainRequirements);
    }

    private static Map<String, IdCredentials> fetchCredentials() {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all()
                .get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            return Collections.emptyMap();
        }
        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        if (StringUtils.isEmpty(credentialID)) {
            return Collections.emptyMap();
        }
        String keyVaultURL = KeyVaultCredentialsLoader.normalizeKeyVaultURL(azureKeyVaultGlobalConfiguration.getKeyVaultURL());
        if (keyVaultURL == null) {
            return Collections.emptyMap();
        }
        return vaultLoader.apply(credentialID, keyVaultURL);
    }

    @Override
    public CredentialsStore getStore(ModelObject object) {
        return object == Jenkins.get() ? store : null;
    }
}

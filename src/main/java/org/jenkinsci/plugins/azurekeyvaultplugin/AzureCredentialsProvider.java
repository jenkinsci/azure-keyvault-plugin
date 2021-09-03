package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.jenkins.keyvault.SecretStringCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.apache.commons.lang3.StringUtils;


@Extension
public class AzureCredentialsProvider extends CredentialsProvider {
    private static final Logger LOG = Logger.getLogger(AzureCredentialsProvider.class.getName());

    private static final String CACHE_KEY = "key";

    private final AzureCredentialsStore store = new AzureCredentialsStore(this);

    private final LoadingCache<String, Collection<IdCredentials>> cache = Caffeine.newBuilder()
        .maximumSize(1L)
        .expireAfterWrite(Duration.ofMinutes(120))
        .refreshAfterWrite(Duration.ofMinutes(10))
        .build(key -> fetchCredentials());

    public void refreshCredentials() {
        cache.refresh(CACHE_KEY);
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> aClass, @Nullable ItemGroup itemGroup,
                                                          @Nullable Authentication authentication) {
        if (ACL.SYSTEM.equals(authentication)) {
            final ArrayList<C> list = new ArrayList<>();
            try {
                Collection<IdCredentials> credentials = cache.get(CACHE_KEY);
                if (credentials == null) {
                    throw new IllegalStateException("Cache is not working");
                }

                for (IdCredentials credential : credentials) {
                    if (aClass.isAssignableFrom(credential.getClass())) {
                        // cast to keep generics happy even though we are assignable..
                        list.add(aClass.cast(credential));
                    }
                    LOG.log(Level.FINEST, "getCredentials {0} does not match", credential.getId());
                }
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
                return Collections.emptyList();
            }
            return list;
        }

        return Collections.emptyList();
    }

    @VisibleForTesting
    static String getSecretName(String itemId) {
        if (StringUtils.isEmpty(itemId)) {
            throw new AzureKeyVaultException("Empty id for key vault item.");
        }
        int index = itemId.lastIndexOf('/');
        if (index < 0) {
            throw new AzureKeyVaultException("Wrong pattern for key vault item id.");
        }
        return itemId.substring(index + 1);
    }

    private static Collection<IdCredentials> fetchCredentials() {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all().get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            throw new AzureKeyVaultException("No global key vault url configured.");
        }

        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        TokenCredential keyVaultCredentials = AzureKeyVaultCredentialRetriever.getCredentialById(credentialID);
        if (keyVaultCredentials == null) {
            return Collections.emptyList();
        }

        try {
            SecretClient client = AzureCredentials.createKeyVaultClient(keyVaultCredentials, azureKeyVaultGlobalConfiguration.getKeyVaultURL());

            List<IdCredentials> credentials = new ArrayList<>();
            for (SecretProperties secretItem : client.listPropertiesOfSecrets()) {
                String id = secretItem.getId();
                Map<String, String> tags = secretItem.getTags();
                if (tags != null && tags.containsKey("username")) {
                    AzureKeyVaultUsernamePasswordCredentials cred = new AzureKeyVaultUsernamePasswordCredentials(CredentialsScope.GLOBAL, getSecretName(id), tags.get("username"), id, credentialID, id);
                    credentials.add(cred);
                } else {
                    SecretStringCredentials cred = new SecretStringCredentials(CredentialsScope.GLOBAL, getSecretName(id), id, credentialID, id);
                    credentials.add(cred);
                }
            }
            return credentials;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public CredentialsStore getStore(ModelObject object) {
        return object == Jenkins.get() ? store : null;
    }

    @Override
    public String getIconClassName() {
        return "icon-azure-key-vault-credentials-store";
    }
}

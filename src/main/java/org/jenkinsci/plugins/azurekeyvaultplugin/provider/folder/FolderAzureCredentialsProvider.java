package org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder;

import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.CredentialsStoreAction;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.jenkins.keyvault.SecretClientCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import hudson.security.Permission;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import net.jcip.annotations.GuardedBy;
import org.acegisecurity.Authentication;
import org.apache.commons.lang3.StringUtils;
import org.jenkins.ui.icon.Icon;
import org.jenkins.ui.icon.IconSet;
import org.jenkins.ui.icon.IconType;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultException;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultUtil;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword.AzureUsernamePasswordCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.KeyVaultSecretRetriever;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;


@Extension(optional = true)
public class FolderAzureCredentialsProvider extends CredentialsProvider {
    private static final Logger LOG = Logger.getLogger(FolderAzureCredentialsProvider.class.getName());

    private static final String CACHE_KEY = "key";
    private static final String DEFAULT_TYPE = "string";

    @GuardedBy("self")
    private static final WeakHashMap<AbstractFolder<?>, FolderAzureKeyVaultCredentialsProperty> emptyProperties =
            new WeakHashMap<>();

    private final LoadingCache<CacheKey, Collection<IdCredentials>> cache = Caffeine.newBuilder()
            .maximumSize(1L)
            .expireAfterWrite(Duration.ofMinutes(120))
            .refreshAfterWrite(Duration.ofMinutes(10))
            .build(FolderAzureCredentialsProvider::fetchCredentials);

    public void refreshCredentials() {
        cache.invalidateAll();
    }

    private static final class CacheKey {
        String credentialID;
        String url;
        String itemName;

        public CacheKey(String credentialID, String url, String itemName) {
            this.credentialID = credentialID;
            this.url = url;
            this.itemName = itemName;
        }


        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CacheKey cacheKey = (CacheKey) o;
            return Objects.equals(credentialID, cacheKey.credentialID) && Objects.equals(url, cacheKey.url) && Objects.equals(itemName, cacheKey.itemName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(credentialID, url, itemName);
        }
    }

    public static FolderAzureCredentialsProvider get() {
        return ExtensionList.lookupSingleton(FolderAzureCredentialsProvider.class);
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> aClass, @Nullable ItemGroup itemGroup,
                                                          @Nullable Authentication authentication) {
        if (ACL.SYSTEM.equals(authentication)) {
            while (itemGroup != null) {
                if (itemGroup instanceof AbstractFolder) {
                    final AbstractFolder<?> folder = (AbstractFolder<?>) itemGroup;
                    FolderAzureKeyVaultCredentialsProperty property = folder.getProperties()
                            .get(FolderAzureKeyVaultCredentialsProperty.class);
                    if (property != null) {
                        final ArrayList<C> list = new ArrayList<>();
                        try {
                            CacheKey key = new CacheKey(property.getCredentialID(), property.getUrl(), property.getOwner().getFullName());
                            Collection<IdCredentials> credentials = cache.get(key);
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
                }
                if (itemGroup instanceof Item) {
                    itemGroup = ((Item) itemGroup).getParent();
                } else {
                    break;
                }
            }
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

    private static Collection<IdCredentials> fetchCredentials(CacheKey key) {

        String credentialID = key.credentialID;
        try {
            SecretClient client = SecretClientCache.get(credentialID, key.url);

            List<IdCredentials> credentials = new ArrayList<>();
            // TODO refactor out duplicate
            for (SecretProperties secretItem : client.listPropertiesOfSecrets()) {
                String id = secretItem.getId();
                Map<String, String> tags = secretItem.getTags();

                if (tags == null) {
                    tags = new HashMap<>();
                }

                String type = tags.getOrDefault("type", DEFAULT_TYPE);

                // initial implementation didn't require a type
                if (tags.containsKey("username") && type.equals(DEFAULT_TYPE)) {
                    type = "username";
                }

                switch (type) {
                    case "string": {
                        AzureSecretStringCredentials cred = new AzureSecretStringCredentials(getSecretName(id), id, new KeyVaultSecretRetriever(client, id));
                        credentials.add(cred);
                    }
                    break;
                    case "username": {
                        AzureUsernamePasswordCredentials cred = new AzureUsernamePasswordCredentials(
                                getSecretName(id), tags.get("username"), id, new KeyVaultSecretRetriever(client, id)
                        );
                        credentials.add(cred);
                    }
                    break;
                    default: {
                        throw new IllegalStateException("Unknown type: " + type);
                    }
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
        if (object instanceof AbstractFolder) {
            final AbstractFolder<?> folder = (AbstractFolder<?>) object;
            FolderAzureKeyVaultCredentialsProperty property = folder.getProperties()
                    .get(FolderAzureKeyVaultCredentialsProperty.class);
            if (property != null) {
                return property.getStore();
            }
            synchronized (emptyProperties) {
                property = emptyProperties.get(folder);
                if (property == null) {
                    property = new FolderAzureKeyVaultCredentialsProperty(folder);
                    emptyProperties.put(folder, property);
                }
            }
            return property.getStore();
        }
        return null;
    }

    @Override
    public String getIconClassName() {
        return "icon-azure-key-vault-credentials-store";
    }

    public static class FolderAzureKeyVaultCredentialsProperty extends AbstractFolderProperty<AbstractFolder<?>> {

        private final FolderAzureCredentialsStore store = new FolderAzureCredentialsStore();
        private String url;
        private String credentialID;

        public FolderAzureKeyVaultCredentialsProperty(AbstractFolder<?> owner) {
            setOwner(owner);
        }

        @DataBoundConstructor
        public FolderAzureKeyVaultCredentialsProperty(String url, String credentialID) {
            this.url = url;
            this.credentialID = credentialID;
        }

        public String getUrl() {
            return url;
        }

        public String getCredentialID() {
            return credentialID;
        }

        public FolderAzureCredentialsStore getStore() {
            return store;
        }

        @NonNull
        private List<Credentials> getCredentials(@NonNull Domain domain) {
            if (Domain.global().equals(domain) && store.hasPermission(CredentialsProvider.VIEW)) {
                FolderAzureCredentialsProvider provider = FolderAzureCredentialsProvider.get();
                return provider.getCredentials(Credentials.class, (ItemGroup) owner, ACL.SYSTEM);
            } else {
                return Collections.emptyList();
            }
        }

        @Extension(optional = true)
        public static class DescriptorImpl extends AbstractFolderPropertyDescriptor {

            /**
             * {@inheritDoc}
             */
            @Override
            public String getDisplayName() {
                return "Azure Key Vault?";
            }

            @SuppressWarnings("unused")
            @POST
            public ListBoxModel doFillCredentialIDItems(@AncestorInPath Item context) {
                return AzureKeyVaultUtil.doFillCredentialIDItems(context);
            }

            @POST
            @SuppressWarnings("unused")
            public FormValidation doTestConnection(
                    @AncestorInPath Item context,
                    @QueryParameter("url") final String keyVaultURL,
                    @QueryParameter("credentialID") final String credentialID
            ) {
                if (context == null) {
                    Jenkins.get().checkPermission(Jenkins.ADMINISTER);
                } else {
                    context.checkPermission(Item.CONFIGURE);
                }

                if (keyVaultURL == null) {
                    return FormValidation.error("Key vault url is required");
                }

                if (credentialID == null) {
                    return FormValidation.error("Credential ID is required");
                }

                try {
                    // TODO needs to add item context
                    SecretClient client = SecretClientCache.get(credentialID, keyVaultURL);

                    Long numberOfSecrets = client.listPropertiesOfSecrets().stream().count();
                    return FormValidation.ok(String.format("Success, found %d secrets in the vault", numberOfSecrets));
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, "Failed testing connection", e);
                    return FormValidation.error(e, e.getMessage());
                }
            }

        }

        private class FolderAzureCredentialsStore extends CredentialsStore {

            private final FolderAzureCredentialsStoreAction action = new FolderAzureCredentialsStoreAction();

            @NonNull
            @Override
            public ModelObject getContext() {
                return owner;
            }

            @Override
            public boolean hasPermission(@NonNull Authentication authentication, @NonNull Permission permission) {
                return owner.getACL().hasPermission(authentication, permission);
            }

            @NonNull
            @Override
            public List<Credentials> getCredentials(@NonNull Domain domain) {
                return FolderAzureKeyVaultCredentialsProperty.this.getCredentials(domain);
            }

            @Override
            public boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials) {
                throw new UnsupportedOperationException(
                        "Jenkins may not add credentials to Azure Key Vault");
            }

            @Override
            public boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials) {
                throw new UnsupportedOperationException(
                        "Jenkins may not remove credentials in Azure Key Vault");
            }

            @Override
            public boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials credentials,
                                             @NonNull Credentials credentials1) {
                throw new UnsupportedOperationException(
                        "Jenkins may not update credentials in Azure Key Vault");
            }

            @Nullable
            @Override
            public CredentialsStoreAction getStoreAction() {
                return action;
            }

        }

        public final class FolderAzureCredentialsStoreAction extends CredentialsStoreAction {

            private static final String ICON_CLASS = "icon-azure-key-vault-credentials-store";

            private FolderAzureCredentialsStoreAction() {
                addIcons();
            }

            private void addIcons() {
                IconSet.icons.addIcon(new Icon(ICON_CLASS + " icon-sm",
                        "azure-keyvault/images/16x16/icon.png",
                        Icon.ICON_SMALL_STYLE, IconType.PLUGIN));
                IconSet.icons.addIcon(new Icon(ICON_CLASS + " icon-md",
                        "azure-keyvault/images/24x24/icon.png",
                        Icon.ICON_MEDIUM_STYLE, IconType.PLUGIN));
                IconSet.icons.addIcon(new Icon(ICON_CLASS + " icon-lg",
                        "azure-keyvault/images/32x32/icon.png",
                        Icon.ICON_LARGE_STYLE, IconType.PLUGIN));
                IconSet.icons.addIcon(new Icon(ICON_CLASS + " icon-xlg",
                        "azure-keyvault/images/48x48/icon.png",
                        Icon.ICON_XLARGE_STYLE, IconType.PLUGIN));
            }

            @Override
            @NonNull
            public CredentialsStore getStore() {
                return FolderAzureKeyVaultCredentialsProperty.this.getStore();
            }

            @Override
            public String getIconFileName() {
                return isVisible()
                        ? "/plugin/azure-keyvault/images/32x32/icon.png"
                        : null;
            }

            @Override
            public String getIconClassName() {
                return isVisible()
                        ? ICON_CLASS
                        : null;
            }

            @Override
            public String getDisplayName() {
                return "Azure Key Vault";
            }
        }

    }

}

package org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.secrets.SecretClient;
import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.CredentialsStoreAction;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.azure.util.AzureCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.ExtensionList;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.model.listeners.ItemListener;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.Permission;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultUtil;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.BaseAzureKeyVaultCredentialsProvider;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.KeyVaultCredentialsLoader;
import org.jenkinsci.plugins.variant.OptionalExtension;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.export.ExportedBean;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.core.Authentication;

/**
 * Serves credentials from a Key Vault configured on a folder to the items in that folder and its sub-folders.
 * <p>
 * Lookups walk from the requesting context up through its parent folders. When the same credential ID is
 * defined in more than one folder the nearest folder wins, matching the folder credentials provider in
 * {@code cloudbees-folder}. Secrets tagged with the {@code SYSTEM} scope are ignored, as there is no
 * Jenkins-internal context inside a folder for them to be used in.
 */
@OptionalExtension(requirePlugins = "cloudbees-folder")
public class FolderAzureCredentialsProvider extends BaseAzureKeyVaultCredentialsProvider {
    private static final Logger LOG = Logger.getLogger(FolderAzureCredentialsProvider.class.getName());

    /**
     * Reads the credentials from a folder's vault, replaced in tests so they don't need a real Key Vault.
     */
    @VisibleForTesting
    static BiFunction<AbstractFolder<?>, VaultKey, Map<String, IdCredentials>> vaultLoader = (folder, key) ->
            KeyVaultCredentialsLoader.load(createClient(folder, key.credentialID(), key.keyVaultURL()), key.keyVaultURL());

    private final LoadingCache<VaultKey, Map<String, IdCredentials>> cache = newCacheBuilder(1000L)
            .build(credentialsLoader(FolderAzureCredentialsProvider::fetchCredentials));

    /**
     * Identifies a vault connection. The folder is part of the key because the credential used to connect
     * to the vault is resolved in the context of that folder.
     */
    @VisibleForTesting
    record VaultKey(String folderFullName, String keyVaultURL, String credentialID) {
    }

    public static FolderAzureCredentialsProvider get() {
        return ExtensionList.lookupSingleton(FolderAzureCredentialsProvider.class);
    }

    public void refreshCredentials() {
        cache.invalidateAll();
    }

    /**
     * Reloads every cached vault in the way a scheduled refresh does, keeping the current entry if the reload fails.
     */
    @VisibleForTesting
    void refreshCachedVaults() {
        cache.refreshAll(cache.asMap().keySet()).exceptionally(e -> null).join();
    }

    /**
     * Drops the cached credentials of a folder and everything beneath it.
     */
    public void refreshCredentials(@NonNull String folderFullName) {
        cache.asMap().keySet().removeIf(key -> key.folderFullName().equals(folderFullName)
                || key.folderFullName().startsWith(folderFullName + "/"));
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentialsInItemGroup(
            @NonNull Class<C> type,
            @Nullable ItemGroup itemGroup,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        if (!isSystem(authentication) || !isLookupSupported(type)) {
            return Collections.emptyList();
        }

        List<C> result = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (AbstractFolder<?> folder : foldersOf(itemGroup)) {
            for (IdCredentials credential : getFolderCredentials(folder)) {
                // nearer folders are visited first, so they win when an ID is defined more than once
                if (type.isInstance(credential) && ids.add(credential.getId())) {
                    result.add(type.cast(credential));
                }
            }
        }
        return result;
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentialsInItem(
            @NonNull Class<C> type,
            @NonNull Item item,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        return getCredentialsInItemGroup(type, contextOf(item), authentication, domainRequirements);
    }

    @CheckForNull
    @Override
    public <C extends IdCredentials> C getCredentialByIdInItemGroup(
            @NonNull String id,
            @NonNull Class<C> type,
            @NonNull ItemGroup<?> itemGroup,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        if (!isSystem(authentication) || !isLookupSupported(type)) {
            return null;
        }

        for (AbstractFolder<?> folder : foldersOf(itemGroup)) {
            IdCredentials credential = getVaultCredentials(folder).get(id);
            // a definition of another type doesn't hide one further up, matching getCredentialsInItemGroup
            if (type.isInstance(credential) && credential.getScope() != CredentialsScope.SYSTEM) {
                return type.cast(credential);
            }
        }
        return null;
    }

    @CheckForNull
    @Override
    public <C extends IdCredentials> C getCredentialByIdInItem(
            @NonNull String id,
            @NonNull Class<C> type,
            @NonNull Item item,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        ItemGroup<?> context = contextOf(item);
        return context == null ? null : getCredentialByIdInItemGroup(id, type, context, authentication, domainRequirements);
    }

    @Override
    public CredentialsStore getStore(ModelObject object) {
        if (object instanceof AbstractFolder<?> folder) {
            FolderAzureKeyVaultCredentialsProperty property = folder.getProperties()
                    .get(FolderAzureKeyVaultCredentialsProperty.class);
            if (property != null) {
                return property.getStore();
            }
        }
        return null;
    }

    private static boolean isSystem(@Nullable Authentication authentication) {
        return authentication == null || ACL.SYSTEM2.equals(authentication);
    }

    @CheckForNull
    private static ItemGroup<?> contextOf(@NonNull Item item) {
        return item instanceof ItemGroup<?> group ? group : item.getParent();
    }

    private static List<AbstractFolder<?>> foldersOf(@Nullable ItemGroup<?> itemGroup) {
        List<AbstractFolder<?>> folders = new ArrayList<>();
        while (itemGroup instanceof Item item) {
            if (itemGroup instanceof AbstractFolder<?> folder) {
                folders.add(folder);
            }
            itemGroup = item.getParent();
        }
        return folders;
    }

    /**
     * @return the credentials from the vault configured on this folder that items in it can use
     */
    @NonNull
    List<IdCredentials> getFolderCredentials(@NonNull AbstractFolder<?> folder) {
        List<IdCredentials> credentials = new ArrayList<>();
        for (IdCredentials credential : getVaultCredentials(folder).values()) {
            if (credential.getScope() == CredentialsScope.SYSTEM) {
                LOG.log(Level.FINEST, "{0} in folder {1} has SYSTEM scope which is not supported in folders. Ignoring credential",
                        new Object[] {credential.getId(), folder.getFullName()});
            } else {
                credentials.add(credential);
            }
        }
        return credentials;
    }

    @NonNull
    private Map<String, IdCredentials> getVaultCredentials(@NonNull AbstractFolder<?> folder) {
        FolderAzureKeyVaultCredentialsProperty property = folder.getProperties()
                .get(FolderAzureKeyVaultCredentialsProperty.class);
        if (property == null) {
            return Collections.emptyMap();
        }
        String keyVaultURL = KeyVaultCredentialsLoader.normalizeKeyVaultURL(property.getUrl());
        if (keyVaultURL == null || StringUtils.isBlank(property.getCredentialID())) {
            return Collections.emptyMap();
        }
        try {
            Map<String, IdCredentials> credentials = cache.get(new VaultKey(folder.getFullName(), keyVaultURL, property.getCredentialID()));
            return credentials == null ? Collections.emptyMap() : credentials;
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault for folder " + folder.getFullName() + ": " + e.getMessage(), e);
            return Collections.emptyMap();
        }
    }

    /**
     * Failures are thrown, see {@link #credentialsLoader} for how the cache handles them.
     */
    private static Map<String, IdCredentials> fetchCredentials(VaultKey key) {
        // refreshes run on a background thread, which can't see the folder without this
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            AbstractFolder<?> folder = Jenkins.get().getItemByFullName(key.folderFullName(), AbstractFolder.class);
            if (folder == null) {
                return Collections.emptyMap();
            }
            return vaultLoader.apply(folder, key);
        }
    }

    /**
     * Connects using a credential visible from the folder, so a folder can use Azure credentials of its own
     * rather than only ones defined globally.
     */
    private static SecretClient createClient(Item context, String credentialID, String keyVaultURL) {
        TokenCredential tokenCredential = AzureCredentials.getCredentialById(context, credentialID);
        if (tokenCredential == null) {
            throw new IllegalStateException("Could not find Azure credential " + credentialID + " from " + context.getFullName());
        }
        return AzureCredentials.createKeyVaultClient(tokenCredential, keyVaultURL);
    }

    /**
     * Drops cached credentials when a folder is reconfigured, moved or deleted, so a stale vault isn't used.
     */
    @OptionalExtension(requirePlugins = "cloudbees-folder")
    public static class FolderListener extends ItemListener {
        @Override
        public void onUpdated(Item item) {
            refresh(item.getFullName());
        }

        @Override
        public void onDeleted(Item item) {
            refresh(item.getFullName());
        }

        @Override
        public void onLocationChanged(Item item, String oldFullName, String newFullName) {
            refresh(oldFullName);
        }

        private static void refresh(String fullName) {
            FolderAzureCredentialsProvider.get().refreshCredentials(fullName);
        }
    }

    public static class FolderAzureKeyVaultCredentialsProperty extends AbstractFolderProperty<AbstractFolder<?>> {

        private final String url;
        private final String credentialID;
        private transient FolderAzureCredentialsStore store;

        @DataBoundConstructor
        public FolderAzureKeyVaultCredentialsProperty(String url, String credentialID) {
            this.url = url;
            this.credentialID = credentialID;
            this.store = new FolderAzureCredentialsStore();
        }

        protected Object readResolve() {
            store = new FolderAzureCredentialsStore();
            return this;
        }

        public String getUrl() {
            return url;
        }

        public String getCredentialID() {
            return credentialID;
        }

        public CredentialsStore getStore() {
            return store;
        }

        @OptionalExtension(requirePlugins = "cloudbees-folder")
        @Symbol("azureKeyVault")
        public static class DescriptorImpl extends AbstractFolderPropertyDescriptor {

            @NonNull
            @Override
            public String getDisplayName() {
                return "Azure Key Vault";
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
                    @QueryParameter("url") final String url,
                    @QueryParameter("credentialID") final String credentialID
            ) {
                if (context == null) {
                    Jenkins.get().checkPermission(Jenkins.ADMINISTER);
                    return FormValidation.error("Save the folder before testing the connection");
                }
                context.checkPermission(Item.CONFIGURE);

                if (StringUtils.isBlank(url)) {
                    return FormValidation.error("Key vault url is required");
                }

                if (StringUtils.isBlank(credentialID)) {
                    return FormValidation.error("Credential ID is required");
                }

                try {
                    SecretClient client = createClient(context, credentialID, url);

                    long numberOfSecrets = client.listPropertiesOfSecrets().stream().count();
                    return FormValidation.ok(String.format("Success, found %d secrets in the vault", numberOfSecrets));
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, "Failed testing connection", e);
                    return FormValidation.error(e, e.getMessage());
                }
            }

            @POST
            @SuppressWarnings("unused")
            public FormValidation doReloadCache(@AncestorInPath Item context) {
                if (context == null) {
                    Jenkins.get().checkPermission(Jenkins.ADMINISTER);
                    return FormValidation.ok();
                }
                context.checkPermission(Item.CONFIGURE);

                FolderAzureCredentialsProvider.get().refreshCredentials(context.getFullName());
                return FormValidation.ok("Cache reloaded");
            }
        }

        private class FolderAzureCredentialsStore extends CredentialsStore {

            private final FolderAzureCredentialsStoreAction action = new FolderAzureCredentialsStoreAction(this);

            FolderAzureCredentialsStore() {
                super(FolderAzureCredentialsProvider.class);
            }

            @NonNull
            @Override
            public ModelObject getContext() {
                return owner;
            }

            /**
             * Credentials are managed in Key Vault, so only viewing them is ever permitted.
             */
            @Override
            public boolean hasPermission2(@NonNull Authentication authentication, @NonNull Permission permission) {
                return CredentialsProvider.VIEW.equals(permission)
                        && owner.getACL().hasPermission2(authentication, permission);
            }

            @NonNull
            @Override
            public List<Credentials> getCredentials(@NonNull Domain domain) {
                if (Domain.global().equals(domain) && hasPermission(CredentialsProvider.VIEW)) {
                    return new ArrayList<>(FolderAzureCredentialsProvider.get().getFolderCredentials(owner));
                }
                return Collections.emptyList();
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
    }

    /**
     * Expose the store. The icons are registered by the global store's action.
     */
    @ExportedBean
    public static final class FolderAzureCredentialsStoreAction extends CredentialsStoreAction {

        private final CredentialsStore store;

        private FolderAzureCredentialsStoreAction(CredentialsStore store) {
            this.store = store;
        }

        @Override
        @NonNull
        public CredentialsStore getStore() {
            return store;
        }

        @Override
        public String getIconClassName() {
            return isVisible()
                    ? "icon-azure-key-vault-credentials-store"
                    : null;
        }

        @Override
        public String getDisplayName() {
            return "Azure Key Vault";
        }
    }
}

package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.jenkins.keyvault.SecretClientCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import hudson.util.Secret;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile.AzureSecretFileCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.sshuserprivatekey.AzureSSHUserPrivateKeyCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword.AzureUsernamePasswordCredentials;


@Extension
public class AzureCredentialsProvider extends CredentialsProvider {
    private static final Logger LOG = Logger.getLogger(AzureCredentialsProvider.class.getName());

    private static final String CACHE_KEY = "key";
    private static final String DEFAULT_TYPE = "string";
    private static final String DEFAULT_SCOPE = "GLOBAL";

    private final AzureCredentialsStore store = new AzureCredentialsStore(this);

    private final LoadingCache<String, Collection<IdCredentials>> cache = Caffeine.newBuilder()
            .maximumSize(1L)
            .expireAfterWrite(Duration.ofMinutes(120))
            .refreshAfterWrite(Duration.ofMinutes(10))
            .build(key -> fetchCredentials());

    public void refreshCredentials() {
        cache.invalidateAll();
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
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type,
                                                          @NonNull Item item,
                                                          Authentication authentication) {
        // scoping to Items is not supported so using null to not expose SYSTEM credentials to Items.
        Objects.requireNonNull(item);
        return getCredentials(type, (ItemGroup)null, authentication);
    }

    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type,
                                                          @NonNull Item item,
                                                          Authentication authentication,
                                                          List<DomainRequirement> domainRequirements) {
        // domain requirements not supported
        return getCredentials(type, item, authentication);
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
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all()
                .get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            throw new AzureKeyVaultException("No global key vault url configured.");
        }

        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        try {
            String keyVaultURL = azureKeyVaultGlobalConfiguration.getKeyVaultURL();
            if (StringUtils.isEmpty(keyVaultURL) || StringUtils.isEmpty(credentialID)) {
                return Collections.emptyList();
            }

            // If keyVaultURL does not have a trailing slash, add one
            if (!keyVaultURL.endsWith("/")) {
                keyVaultURL += "/";
            }

            SecretClient client = SecretClientCache.get(credentialID, keyVaultURL);

            String labelSelector = extractLabelSelector();
            List<IdCredentials> credentials = new ArrayList<>();
            for (SecretProperties secretItem : client.listPropertiesOfSecrets()) {
                String id = secretItem.getId();
                try {
                    Map<String, String> tags = secretItem.getTags();

                    if (tags == null) {
                        tags = new HashMap<>();
                    }

                    if (StringUtils.isNotBlank(labelSelector)) {
                        String jenkinsLabels = tags.getOrDefault("jenkins-label", "");
                        List<String> labelSelectors = Arrays.asList(jenkinsLabels.split(","));
                        if (!labelSelectors.contains(labelSelector)) {
                            continue;
                        }
                    }

                    String type = tags.getOrDefault("type", DEFAULT_TYPE);
                    String jenkinsID = tags.getOrDefault("jenkinsID", getSecretName(id));
                    String description = tags.getOrDefault("description", "");
                    String labelScope = tags.getOrDefault("scope", DEFAULT_SCOPE).toUpperCase();

                    CredentialsScope scope = CredentialsScope.GLOBAL;

                    if (tags.containsKey("scope") && labelScope.equals("SYSTEM")) {
                        scope = CredentialsScope.SYSTEM;
                    }

                    // initial implementation didn't require a type
                    if (tags.containsKey("username") && type.equals(DEFAULT_TYPE)) {
                        type = "username";
                    }

                    switch (type) {
                        case "string": {
                            AzureSecretStringCredentials cred = new AzureSecretStringCredentials(scope, jenkinsID, description, new KeyVaultSecretRetriever(client, id));
                            credentials.add(cred);
                            break;
                        }
                        case "secretFile": {
                            String fileName = tags.get("fileName");
                            if(fileName.isEmpty()){
                                fileName = "defaultFileName.txt";
                            }
                            AzureSecretFileCredentials cred = new AzureSecretFileCredentials(scope, jenkinsID, description, fileName, new KeyVaultSecretRetriever(client, id));
                            credentials.add(cred);
                            break;
                        }
                        case "username": {
                            AzureUsernamePasswordCredentials cred = new AzureUsernamePasswordCredentials(
                                    scope, jenkinsID, tags.get("username"), description, new KeyVaultSecretRetriever(client, id)
                            );
                            credentials.add(cred);
                            break;
                        }
                        case "sshUserPrivateKey": {
                            String usernameSecretTag = tags.get("username-is-secret");
                            String passphraseID = tags.get("passphrase-id");
                            Secret passphrase = null;
                            boolean usernameSecret = false;
                            if (StringUtils.isNotBlank(usernameSecretTag)) {
                                usernameSecret = Boolean.parseBoolean(usernameSecretTag);
                            }
                            if (StringUtils.isNotBlank(passphraseID)) {
                                try {
                                    passphrase = new KeyVaultSecretRetriever(client, keyVaultURL + "secrets/" + passphraseID).get();
                                } catch (Exception e) {
                                    LOG.log(Level.WARNING, "Could not find passphrase with ID " + passphraseID + " in KeyVault.");
                                    continue;
                                }

                            }
                            AzureSSHUserPrivateKeyCredentials cred = new AzureSSHUserPrivateKeyCredentials(
                                    scope, jenkinsID, description, tags.get("username"), usernameSecret, passphrase, new KeyVaultSecretRetriever(client, id)
                            );
                            credentials.add(cred);
                            break;
                        }
                        default: {
                            throw new IllegalStateException("Unknown type: " + type);
                        }
                    }
                }
                catch(Exception e){
                    LOG.log(Level.WARNING, "Error retrieving secret with id " + id + " from Azure KeyVault: " + e.getMessage(), e);
                }
            }
            return credentials;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    public static String extractLabelSelector() {
        return StringUtils.isNotBlank(System.getenv("AZURE_KEYVAULT_LABEL_SELECTOR")) ? System.getenv("AZURE_KEYVAULT_LABEL_SELECTOR") : System.getProperty("jenkins.azure-keyvault.label_selector");
    }

    private static class KeyVaultSecretRetriever implements Supplier<Secret> {

        private final transient SecretClient client;
        private final String secretId;

        public KeyVaultSecretRetriever(SecretClient secretClient, String secretId) {
            this.client = secretClient;
            this.secretId = secretId;
        }

        public String retrieveSecret() {
            int NAME_POSITION = 2;
            int VERSION_POSITION = 3;
            URL secretIdentifierUrl;
            try {
                secretIdentifierUrl = new URL(secretId);
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }

            // old SDK supports secret identifier which is a full URI to the secret
            // the new SDK doesn't seem to support it to we parse it to get the values we need
            // https://mine.vault.azure.net/secrets/<name>/<version>
            String[] split = secretIdentifierUrl.getPath().split("/");

            if (split.length == NAME_POSITION + 1) {
                return client.getSecret(split[NAME_POSITION]).getValue();
            }
            return client.getSecret(split[NAME_POSITION], split[VERSION_POSITION]).getValue();
        }

        @Override
        public Secret get() {
            return Secret.fromString(retrieveSecret());
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

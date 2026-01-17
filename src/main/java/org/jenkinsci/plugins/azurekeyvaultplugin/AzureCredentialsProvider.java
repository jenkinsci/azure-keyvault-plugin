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
import edu.umd.cs.findbugs.annotations.CheckForNull;
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
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.certificate.AzureCertificateCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile.AzureSecretFileCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.sshuserprivatekey.AzureSSHUserPrivateKeyCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword.AzureUsernamePasswordCredentials;
import org.springframework.security.core.Authentication;


@Extension
public class AzureCredentialsProvider extends CredentialsProvider {
    private static final Logger LOG = Logger.getLogger(AzureCredentialsProvider.class.getName());

    private static final String CACHE_KEY = "key";
    private static final String DEFAULT_TYPE = "string";
    private static final String DEFAULT_SCOPE = "GLOBAL";

    private final AzureCredentialsStore store = new AzureCredentialsStore(this);

    private final LoadingCache<String, Map<String, IdCredentials>> cache = Caffeine.newBuilder()
            .maximumSize(1L)
            .expireAfterWrite(Duration.ofMinutes(120))
            .refreshAfterWrite(Duration.ofMinutes(10))
            .build(key -> fetchCredentials());

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
        if (ACL.SYSTEM2.equals(authentication)) {
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
        if (ACL.SYSTEM2.equals(authentication)) {
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

    private static String getKeyVaultURL(AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration) {
        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        String keyVaultURL = azureKeyVaultGlobalConfiguration.getKeyVaultURL();
        if (StringUtils.isEmpty(keyVaultURL) || StringUtils.isEmpty(credentialID)) {
            return null;
        }

        // If keyVaultURL does not have a trailing slash, add one
        if (!keyVaultURL.endsWith("/")) {
            keyVaultURL += "/";
        }
        return keyVaultURL;
    }

    private static Map<String, IdCredentials> fetchCredentials() {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all()
                .get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            throw new AzureKeyVaultException("No global key vault url configured.");
        }
        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        try {
            String keyVaultURL = getKeyVaultURL(azureKeyVaultGlobalConfiguration);
            SecretClient client = SecretClientCache.get(credentialID, keyVaultURL);

            String configuredLabelSelector = extractLabelSelector();
            Map<String, IdCredentials> credentials = new HashMap<>();
            for (SecretProperties secretItem : client.listPropertiesOfSecrets()) {
                IdCredentials cred = mapPropertiesToCredentials(secretItem, configuredLabelSelector, client, keyVaultURL);
                if (cred != null) {
                    credentials.put(cred.getId(), cred);
                }
            }
            return credentials;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Error retrieving secrets from Azure KeyVault: " + e.getMessage(), e);
            return Collections.emptyMap();
        }
    }

    private static IdCredentials mapPropertiesToCredentials(
            SecretProperties secretItem, String configuredLabelSelector, SecretClient client, String keyVaultURL
    ) {
        String id = secretItem.getId();
        try {
            Map<String, String> tags = secretItem.getTags();

            if (tags == null) {
                tags = new HashMap<>();
            }
            if (StringUtils.isNotBlank(configuredLabelSelector)) {
                String secretLabelSelector = tags.getOrDefault("jenkins-label", "");
                List<String> secretLabels = Arrays.asList(secretLabelSelector.split(","));
                List<String> configuredLabels = Arrays.asList(configuredLabelSelector.split(","));
                if (secretLabels.stream().filter(configuredLabels::contains).findAny().isEmpty()) {
                    return null;
                }
            }

            String type = tags.getOrDefault("type", DEFAULT_TYPE);
            String jenkinsID = tags.getOrDefault("jenkinsID", getSecretName(id));
            String description = tags.getOrDefault("description", "");
            String labelScope = tags.getOrDefault("scope", DEFAULT_SCOPE).toUpperCase();

            CredentialsScope scope = CredentialsScope.GLOBAL;

            if (tags.containsKey("scope") && labelScope.equalsIgnoreCase("SYSTEM")) {
                scope = CredentialsScope.SYSTEM;
            }

            // initial implementation didn't require a type
            if (tags.containsKey("username") && type.equals(DEFAULT_TYPE)) {
                type = "username";
            }

            switch (type) {
                case "string": {
                    return new AzureSecretStringCredentials(scope, jenkinsID, description, new KeyVaultSecretRetriever(client, id));
                }
                case "secretFile": {
                    String fileName = tags.get("fileName");
                    if(fileName.isEmpty()){
                        fileName = getSecretName(id) + ".txt";
                    }
                    return new AzureSecretFileCredentials(scope, jenkinsID, description, fileName, new KeyVaultSecretRetriever(client, id));
                }
                case "username": {
                    return new AzureUsernamePasswordCredentials(
                            scope, jenkinsID, tags.get("username"), description, new KeyVaultSecretRetriever(client, id)
                    );
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
                            return null;
                        }

                    }
                    return new AzureSSHUserPrivateKeyCredentials(
                            scope, jenkinsID, description, tags.get("username"), usernameSecret, passphrase, new KeyVaultSecretRetriever(client, id)
                    );
                }
                case "certificate": {
                    String passwordId = tags.get("password-id");
                    Supplier<Secret> password = () -> Secret.fromString("");
                    if (StringUtils.isNotBlank(passwordId)) {
                        try {
                            password = new KeyVaultSecretRetriever(client, keyVaultURL + "secrets/" + passwordId);
                        } catch (Exception e) {
                            LOG.log(Level.WARNING, "Could not find password with ID " + passwordId + " in KeyVault.");
                            return null;
                        }
                    }
                    return new AzureCertificateCredentials(
                        scope,
                        jenkinsID,
                        description,
                        password,
                        new KeyVaultSecretRetriever(client, id)
                    );
                }
                default: {
                    throw new IllegalStateException("Unknown type: " + type);
                }
            }
        }
        catch(Exception e){
            LOG.log(Level.WARNING, "Error retrieving secret with id " + id + " from Azure KeyVault: " + e.getMessage(), e);
        }
        return null;
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

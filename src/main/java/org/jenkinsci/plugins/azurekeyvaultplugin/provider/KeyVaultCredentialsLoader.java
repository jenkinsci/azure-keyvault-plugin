package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.util.Secret;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultException;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.certificate.AzureCertificateCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.githubapp.GitHubAppCredentialsFactory;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile.AzureSecretFileCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.sshuserprivatekey.AzureSSHUserPrivateKeyCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword.AzureUsernamePasswordCredentials;

/**
 * Turns the secrets in a Key Vault into Jenkins credentials, shared by the global and folder providers.
 */
public final class KeyVaultCredentialsLoader {
    private static final Logger LOG = Logger.getLogger(KeyVaultCredentialsLoader.class.getName());

    private static final String DEFAULT_TYPE = "string";
    private static final String DEFAULT_SCOPE = "GLOBAL";

    private KeyVaultCredentialsLoader() {
    }

    /**
     * Lists every secret in the vault and maps the ones Jenkins understands to credentials, keyed by credential ID.
     *
     * @param keyVaultURL the vault URL, with a trailing slash (see {@link #normalizeKeyVaultURL(String)})
     */
    public static Map<String, IdCredentials> load(SecretClient client, String keyVaultURL) {
        String configuredLabelSelector = extractLabelSelector();
        Map<String, IdCredentials> credentials = new HashMap<>();
        for (SecretProperties secretItem : client.listPropertiesOfSecrets()) {
            IdCredentials cred = mapPropertiesToCredentials(secretItem, configuredLabelSelector, client, keyVaultURL);
            if (cred != null) {
                credentials.put(cred.getId(), cred);
            }
        }
        return credentials;
    }

    /**
     * @return the URL with a trailing slash, or {@code null} if it is blank
     */
    @CheckForNull
    public static String normalizeKeyVaultURL(@CheckForNull String keyVaultURL) {
        if (StringUtils.isBlank(keyVaultURL)) {
            return null;
        }

        // If keyVaultURL does not have a trailing slash, add one
        if (!keyVaultURL.endsWith("/")) {
            keyVaultURL += "/";
        }
        return keyVaultURL;
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
                case "githubApp": {
                    // GitHubAppCredentials comes from the optional github-branch-source plugin. Confirm
                    // it is installed *before* touching GitHubAppCredentialsFactory, which is the only
                    // class that references it: that call is what loads those plugin classes, so the
                    // guard keeps a missing optional plugin from breaking this (or any other) credential.
                    if (Jenkins.get().getPluginManager().getPlugin("github-branch-source") == null) {
                        LOG.log(Level.WARNING, "Skipping GitHub App credential {0}: github-branch-source plugin is not installed", jenkinsID);
                        return null;
                    }
                    return GitHubAppCredentialsFactory.create(scope, jenkinsID, description, tags, new KeyVaultSecretRetriever(client, id));
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

    private static String extractLabelSelector() {
        return StringUtils.isNotBlank(System.getenv("AZURE_KEYVAULT_LABEL_SELECTOR")) ? System.getenv("AZURE_KEYVAULT_LABEL_SELECTOR") : System.getProperty("jenkins.azure-keyvault.label_selector");
    }
}

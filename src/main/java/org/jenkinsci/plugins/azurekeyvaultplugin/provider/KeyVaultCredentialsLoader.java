package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultException;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;

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

            AzureKeyVaultCredentialsAdapter adapter = AzureKeyVaultCredentialsAdapter.forType(type);
            if (adapter == null) {
                LOG.log(Level.WARNING, "Skipping secret {0}: no credentials adapter for type {1}", new Object[] {id, type});
                return null;
            }
            AzureKeyVaultSecretContext context = new AzureKeyVaultSecretContext(
                    scope, jenkinsID, description, getSecretName(id), tags,
                    new KeyVaultSecretRetriever(client, id),
                    secretName -> new KeyVaultSecretRetriever(client, keyVaultURL + "secrets/" + secretName)
            );
            return adapter.adapt(context);
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

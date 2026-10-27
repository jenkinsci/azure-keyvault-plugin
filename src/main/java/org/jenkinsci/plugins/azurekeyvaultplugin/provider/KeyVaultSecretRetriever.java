package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.azure.security.keyvault.secrets.SecretClient;
import hudson.util.Secret;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.function.Supplier;

public class KeyVaultSecretRetriever implements Supplier<Secret> {

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

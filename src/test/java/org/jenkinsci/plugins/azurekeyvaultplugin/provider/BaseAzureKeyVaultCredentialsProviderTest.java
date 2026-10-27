package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.github.benmanes.caffeine.cache.CacheLoader;
import hudson.util.Secret;
import java.util.Map;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BaseAzureKeyVaultCredentialsProviderTest {

    private static final CacheLoader<String, Map<String, IdCredentials>> FAILING =
            BaseAzureKeyVaultCredentialsProvider.credentialsLoader(key -> {
                throw new IllegalStateException("vault unavailable");
            });

    @Test
    void failedFirstLoadLoadsNoCredentials() throws Exception {
        assertThat(FAILING.load("key"), is(anEmptyMap()));
    }

    @Test
    void failedRefreshIsRethrownSoTheCacheKeepsTheOldCredentials() {
        Map<String, IdCredentials> old = Map.of("id",
                new AzureSecretStringCredentials(CredentialsScope.GLOBAL, "id", "", () -> Secret.fromString("value")));

        assertThrows(IllegalStateException.class, () -> FAILING.reload("key", old));
    }
}

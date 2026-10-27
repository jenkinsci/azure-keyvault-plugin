package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyVaultCredentialsLoaderTest {

    @Test
    void testGenerateKeyvaultItemName_wrong_pattern() {
        Throwable exception = assertThrows(AzureKeyVaultException.class, () ->
            KeyVaultCredentialsLoader.getSecretName("pattern"));
        assertTrue(exception.getMessage().contains("Wrong pattern for key vault item id."));
    }

    @Test
    void testGenerateKeyvaultItemName() {
        String secretItemName = KeyVaultCredentialsLoader.getSecretName("https://myvault.vault.azure" +
                ".net/secrets/mysecret");
        assertEquals("mysecret", secretItemName);
        String certificateItemName = KeyVaultCredentialsLoader.getSecretName("https://myvault.vault.azure.net/certificates/mycertificate");
        assertEquals("mycertificate", certificateItemName);
    }
}

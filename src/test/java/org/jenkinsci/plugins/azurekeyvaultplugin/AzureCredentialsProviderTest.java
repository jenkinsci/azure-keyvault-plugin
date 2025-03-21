package org.jenkinsci.plugins.azurekeyvaultplugin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AzureCredentialsProviderTest {

    @Test
    void testGenerateKeyvaultItemName_wrong_pattern() {
        Throwable exception = assertThrows(AzureKeyVaultException.class, () ->
            AzureCredentialsProvider.getSecretName("pattern"));
        assertTrue(exception.getMessage().contains("Wrong pattern for key vault item id."));
    }

    @Test
    void testGenerateKeyvaultItemName() {
        String secretItemName = AzureCredentialsProvider.getSecretName("https://myvault.vault.azure" +
                ".net/secrets/mysecret");
        assertEquals("mysecret", secretItemName);
        String certificateItemName = AzureCredentialsProvider.getSecretName("https://myvault.vault.azure.net/certificates/mycertificate");
        assertEquals("mycertificate", certificateItemName);
    }
}

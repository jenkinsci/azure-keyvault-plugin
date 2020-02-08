package org.jenkinsci.plugins.azurekeyvaultplugin;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static junit.framework.TestCase.assertEquals;

public class AzureCredentialsProviderTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testGenerateKeyvaultItemName_wrong_pattern() throws Throwable {
        expectedException.expect(AzureKeyVaultException.class);
        expectedException.expectMessage("Wrong pattern for key vault item id.");
        AzureCredentialsProvider.getSecretName("pattern");
    }

    @Test
    public void testGenerateKeyvaultItemName() throws Throwable {
        String secretItemName = AzureCredentialsProvider.getSecretName("https://myvault.vault.azure" +
                ".net/secrets/mysecret");
        assertEquals("mysecret", secretItemName);
        String certificateItemName = AzureCredentialsProvider.getSecretName("https://myvault.vault.azure.net/certificates/mycertificate");
        assertEquals("mycertificate", certificateItemName);
    }
}

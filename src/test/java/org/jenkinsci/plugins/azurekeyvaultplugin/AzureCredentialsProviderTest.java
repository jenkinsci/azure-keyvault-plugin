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
        AzureCredentialsProvider.generateKeyvaultItemName("wrong/pattern");
    }

    @Test
    public void testGenerateKeyvaultItemName() throws Throwable {
        String secretItemName = AzureCredentialsProvider.generateKeyvaultItemName("https://myvault.vault.azure" +
                ".net/secrets/mysecret");
        assertEquals("secrets/mysecret", secretItemName);
        String certificateItemName = AzureCredentialsProvider.generateKeyvaultItemName("https://myvault.vault.azure.net/certificates/mycertificate");
        assertEquals("certificates/mycertificate", certificateItemName);
    }
}

package org.jenkinsci.plugins.azurekeyvaultplugin;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;

public class AzureCredentialsProviderTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testGenerateKeyvaultItemName_wrong_pattern() throws Throwable {
        expectedException.expect(AzureKeyVaultException.class);
        expectedException.expectMessage("Wrong pattern for key vault item id.");
        AzureCredentialsProvider provider = new AzureCredentialsProvider();
        try {
            Method generateKeyvaultItemName = AzureCredentialsProvider.class.getDeclaredMethod("generateKeyvaultItemName"
                    , String.class);
            generateKeyvaultItemName.setAccessible(true);
            String test = (String) generateKeyvaultItemName.invoke(provider, "wrong/pattern");
        } catch (NoSuchMethodException | IllegalAccessException e) {
            fail();
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    @Test
    public void testGenerateKeyvaultItemName() throws Throwable {
        AzureCredentialsProvider provider = new AzureCredentialsProvider();
        try {
            Method generateKeyvaultItemName = AzureCredentialsProvider.class.getDeclaredMethod("generateKeyvaultItemName"
                    , String.class);
            generateKeyvaultItemName.setAccessible(true);
            String secretItemName = (String) generateKeyvaultItemName.invoke(provider, "https://myvault.vault.azure" +
                    ".net/secrets/mysecret");
            assertEquals("secrets/mysecret", secretItemName);
            String certificateItemName = (String) generateKeyvaultItemName.invoke(provider, "https://myvault.vault" +
                    ".azure" +
                    ".net/certificates/mycertificate");
            assertEquals("certificates/mycertificate", certificateItemName);
        } catch (NoSuchMethodException | IllegalAccessException e) {
            fail();
        }
    }
}

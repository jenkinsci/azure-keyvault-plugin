package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.azure.util.AzureImdsCredentials;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class AzureKeyVaultGlobalConfigurationSystemPropertySPTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void before() {
        System.setProperty("jenkins.azure-keyvault.url", "https://mine.vault.azure.net");
        System.setProperty("jenkins.azure-keyvault.sp.client_id", "1234");
        System.setProperty("jenkins.azure-keyvault.sp.client_secret", "1255534");
        System.setProperty("jenkins.azure-keyvault.sp.subscription_id", "5678");
        System.setProperty("jenkins.azure-keyvault.sp.tenant_id", "tenant_id");
    }

    @After
    public void after() {
        System.clearProperty("jenkins.azure-keyvault.url");
        System.clearProperty("jenkins.azure-keyvault.sp.client_id");
        System.clearProperty("jenkins.azure-keyvault.sp.client_secret");
        System.clearProperty("jenkins.azure-keyvault.sp.subscription_id");
        System.clearProperty("jenkins.azure-keyvault.sp.tenant_id");
    }

    @Test
    public void testValuesSet() {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine.vault.azure.net"));

        Credentials credentials = SystemCredentialsProvider.getInstance().getCredentials().get(0);

        assertThat(credentials, instanceOf(AzureCredentials.class));
        AzureCredentials azureCredentials = (AzureCredentials) credentials;

        assertThat(azureCredentials.getClientId(), is("1234"));
        assertThat(azureCredentials.getPlainClientSecret(), is("1255534"));
        assertThat(azureCredentials.getSubscriptionId(), is("5678"));
        assertThat(azureCredentials.getTenant(), is("tenant_id"));

    }
}

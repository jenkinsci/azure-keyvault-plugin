package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureCredentials;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class AzureKeyVaultGlobalConfigurationSystemPropertySPSecretFileTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void before() {
        System.setProperty("jenkins.azure-keyvault.url", "https://mine.vault.azure.net");
        System.setProperty("jenkins.azure-keyvault.sp.client_id", "1234");
        System.setProperty("jenkins.azure-keyvault.sp.client_secret_file", "src/test/resources/org/jenkinsci/plugins/azurekeyvaultplugin/secretfile");
        System.setProperty("jenkins.azure-keyvault.sp.subscription_id", "5678");
        System.setProperty("jenkins.azure-keyvault.sp.tenant_id", "tenant_id");

    }

    @After
    public void after() {
        System.clearProperty("jenkins.azure-keyvault.url");
        System.clearProperty("jenkins.azure-keyvault.sp.client_id");
        System.clearProperty("jenkins.azure-keyvault.sp.client_secret_file");
        System.clearProperty("jenkins.azure-keyvault.sp.subscription_id");
        System.clearProperty("jenkins.azure-keyvault.sp.tenant_id");
        System.clearProperty("jenkins.azure-keyvault.uami.enabled");
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

        // Test updating value
        System.setProperty("jenkins.azure-keyvault.url", "https://mine2.vault.azure.net");
        System.setProperty("jenkins.azure-keyvault.sp.client_id", "5678");
        System.setProperty("jenkins.azure-keyvault.sp.client_secret", "99999");
        System.setProperty("jenkins.azure-keyvault.sp.subscription_id", "9999");
        System.setProperty("jenkins.azure-keyvault.sp.tenant_id", "11111");

        configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine2.vault.azure.net"));

        List<Credentials> credentialsList = SystemCredentialsProvider.getInstance().getCredentials();
        assertThat(credentialsList.size(), is(1));

        AzureCredentials azureCredentialsUpdated = (AzureCredentials) credentialsList.get(0);

        assertThat(azureCredentialsUpdated.getClientId(), is("5678"));
        assertThat(azureCredentialsUpdated.getPlainClientSecret(), is("99999"));
        assertThat(azureCredentialsUpdated.getSubscriptionId(), is("9999"));
        assertThat(azureCredentialsUpdated.getTenant(), is("11111"));
    }
}

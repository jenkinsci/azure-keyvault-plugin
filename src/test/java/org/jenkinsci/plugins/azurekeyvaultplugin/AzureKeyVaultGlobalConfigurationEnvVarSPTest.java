package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureCredentials;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

@WithJenkins
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_URL", value = "https://mine.vault.azure.net")
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_SP_CLIENT_ID", value = "1234")
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_SP_CLIENT_SECRET", value = "1255534")
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_SP_SUBSCRIPTION_ID", value = "5678")
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_SP_TENANT_ID", value = "tenant_id")
class AzureKeyVaultGlobalConfigurationEnvVarSPTest {

    @Test
    void testValuesSet(JenkinsRule j) {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
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

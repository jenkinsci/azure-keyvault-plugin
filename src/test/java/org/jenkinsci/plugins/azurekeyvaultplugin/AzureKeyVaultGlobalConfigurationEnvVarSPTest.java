package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureCredentials;
import io.jenkins.plugins.casc.misc.EnvVarsRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class AzureKeyVaultGlobalConfigurationEnvVarSPTest {

    public final JenkinsRule j = new JenkinsRule();

    @Rule
    public RuleChain chain = RuleChain
            .outerRule(new EnvVarsRule()
                    .set("AZURE_KEYVAULT_URL", "https://mine.vault.azure.net")
                    .set("AZURE_KEYVAULT_SP_CLIENT_ID", "1234")
                    .set("AZURE_KEYVAULT_SP_CLIENT_SECRET", "1255534")
                    .set("AZURE_KEYVAULT_SP_SUBSCRIPTION_ID", "5678")
                    .set("AZURE_KEYVAULT_SP_TENANT_ID", "tenant_id")
            )
            .around(j);

    @Test
    public void testValuesSet() {
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

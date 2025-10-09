package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureImdsCredentials;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

@WithJenkins
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_URL", value = "https://mine.vault.azure.net")
@SetEnvironmentVariable(key = "AZURE_KEYVAULT_UAMI_ENABLED", value = "true")
class AzureKeyVaultGlobalConfigurationEnvVarUamiTest {

    @Test
    void testValuesSet(JenkinsRule j) {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine.vault.azure.net"));

        Credentials credentials = SystemCredentialsProvider.getInstance().getCredentials().get(0);

        assertThat(credentials, instanceOf(AzureImdsCredentials.class));
        assertThat(credentials.getScope(), is(CredentialsScope.GLOBAL));
    }

    @Test
    @SetEnvironmentVariable(key = "AZURE_KEYVAULT_SP_SCOPE", value = "SYSTEM")
    void testValuesSetWithScope(JenkinsRule j) {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine.vault.azure.net"));

        Credentials credentials = SystemCredentialsProvider.getInstance().getCredentials().get(0);

        assertThat(credentials, instanceOf(AzureImdsCredentials.class));
        assertThat(credentials.getScope(), is(CredentialsScope.SYSTEM));
    }
}

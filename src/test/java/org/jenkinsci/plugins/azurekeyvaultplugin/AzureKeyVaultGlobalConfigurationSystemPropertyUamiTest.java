package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureImdsCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

@WithJenkins
class AzureKeyVaultGlobalConfigurationSystemPropertyUamiTest {

    @BeforeEach
    void before() {
        System.setProperty("jenkins.azure-keyvault.url", "https://mine.vault.azure.net");
        System.setProperty("jenkins.azure-keyvault.uami.enabled", "true");
    }

    @AfterEach
    void after() {
        System.clearProperty("jenkins.azure-keyvault.url");
        System.clearProperty("jenkins.azure-keyvault.uami.enabled");
    }

    @Test
    void testValuesSet(JenkinsRule j) {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine.vault.azure.net"));

        Credentials credentials = SystemCredentialsProvider.getInstance().getCredentials().get(0);

        assertThat(credentials, instanceOf(AzureImdsCredentials.class));
    }
}

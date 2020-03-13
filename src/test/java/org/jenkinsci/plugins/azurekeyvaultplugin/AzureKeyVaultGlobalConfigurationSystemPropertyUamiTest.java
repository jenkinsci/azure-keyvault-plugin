package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureImdsCredentials;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class AzureKeyVaultGlobalConfigurationSystemPropertyUamiTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void before() {
        System.setProperty("jenkins.azure-keyvault.url", "https://mine.vault.azure.net");
        System.setProperty("jenkins.azure-keyvault.uami.enabled", "true");
    }

    @After
    public void after() {
        System.clearProperty("jenkins.azure-keyvault.url");
        System.clearProperty("jenkins.azure-keyvault.uami.enabled");
    }

    @Test
    public void testValuesSet() {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine.vault.azure.net"));

        Credentials credentials = SystemCredentialsProvider.getInstance().getCredentials().get(0);

        assertThat(credentials, instanceOf(AzureImdsCredentials.class));
    }
}

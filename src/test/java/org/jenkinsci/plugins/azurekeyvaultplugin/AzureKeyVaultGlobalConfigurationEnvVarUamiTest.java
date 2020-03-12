package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.microsoft.azure.util.AzureImdsCredentials;
import io.jenkins.plugins.casc.misc.EnvVarsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class AzureKeyVaultGlobalConfigurationEnvVarUamiTest {
    public final JenkinsRule j = new JenkinsRule();

    @Rule
    public RuleChain chain = RuleChain
            .outerRule(new EnvVarsRule()
                    .set("AZURE_KEYVAULT_URL", "https://mine.vault.azure.net")
                    .set("AZURE_KEYVAULT_UAMI_ENABLED", "true")
                    )
            .around(j);

    @Test
    public void testValuesSet() {
        AzureKeyVaultGlobalConfiguration configuration = AzureKeyVaultGlobalConfiguration.get();

        assertThat(configuration.getCredentialID(), is(AzureKeyVaultGlobalConfiguration.GENERATED_ID));
        assertThat(configuration.getKeyVaultURL(), is("https://mine.vault.azure.net"));

        Credentials credentials = SystemCredentialsProvider.getInstance().getCredentials().get(0);

        assertThat(credentials, instanceOf(AzureImdsCredentials.class));
    }
}

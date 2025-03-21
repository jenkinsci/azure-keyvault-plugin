package org.jenkinsci.plugins.azurekeyvaultplugin;

import java.util.Collections;
import java.util.List;
import org.jenkinsci.plugins.workflow.cps.SnippetizerTester;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class AzureKeyVaultStepTest {

    @Test
    void configRoundTrip(JenkinsRule j) throws Exception {
        SnippetizerTester st = new SnippetizerTester(j);
        List<AzureKeyVaultSecret> secrets = Collections.singletonList(new AzureKeyVaultSecret("Secret", "hi", "HI"));
        AzureKeyVaultStep step = new AzureKeyVaultStep(secrets);
        st.assertRoundTrip(step, """
                azureKeyVault([[envVariable: 'HI', name: 'hi', secretType: 'Secret']]) {
                    // some block
                }""");
        step.setCredentialID("credId");
        st.assertRoundTrip(step, """
                azureKeyVault(credentialID: 'credId', secrets: [[envVariable: 'HI', name: 'hi', secretType: 'Secret']]) {
                    // some block
                }""");
        step.setKeyVaultURL("https://mine.vault.azure.net");
        st.assertRoundTrip(step, """
                azureKeyVault(credentialID: 'credId', keyVaultURL: 'https://mine.vault.azure.net', secrets: [[envVariable: 'HI', name: 'hi', secretType: 'Secret']]) {
                    // some block
                }""");
    }
}

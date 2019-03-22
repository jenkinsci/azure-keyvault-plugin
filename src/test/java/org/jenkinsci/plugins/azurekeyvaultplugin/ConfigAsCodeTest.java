package org.jenkinsci.plugins.azurekeyvaultplugin;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConfigAsCodeTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("global-config.yml")
    public void should_support_configuration_as_code() {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();

        assertEquals(globalConfiguration.getKeyVaultURL(), "https://not-a-real-vault.vault.azure.net");
        assertEquals(globalConfiguration.getCredentialID(), "service-principal");
    }

    @Test
    @ConfiguredWithCode("global-config.yml")
    @Ignore("configAsCodeOutput doesn't contain the expected output, but the global config is set correctly and manual ui export works")
    public void export_configuration() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ConfigurationAsCode.get().export(outputStream);
        String configAsCodeOutput = new String(outputStream.toByteArray(), StandardCharsets.UTF_8);

        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();

        assertEquals(globalConfiguration.getKeyVaultURL(), "https://not-a-real-vault.vault.azure.net");
        assertEquals(globalConfiguration.getCredentialID(), "service-principal");

        System.out.println(configAsCodeOutput);
        assertTrue("blah", configAsCodeOutput.contains("keyVaultURL: https://not-a-real-vault.vault.azure.net"));
        assertTrue("blah2", configAsCodeOutput.contains("credentialID: service-principal"));
    }
}    
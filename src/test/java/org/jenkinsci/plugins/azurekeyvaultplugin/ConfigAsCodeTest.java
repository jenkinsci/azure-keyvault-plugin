package org.jenkinsci.plugins.azurekeyvaultplugin;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
    public void export_configuration() throws Exception {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();

        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        final Configurator c = context.lookupOrFail(AzureKeyVaultGlobalConfiguration.class);

        @SuppressWarnings("unchecked")
        CNode node = c.describe(globalConfiguration, context);
        assertNotNull(node);
        final Mapping mapping = node.asMapping();

        assertEquals(mapping.getScalarValue("keyVaultURL"), "https://not-a-real-vault.vault.azure.net");
        assertEquals(mapping.getScalarValue("credentialID"), "service-principal");
    }
}    
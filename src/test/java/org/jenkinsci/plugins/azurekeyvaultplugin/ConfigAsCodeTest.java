package org.jenkinsci.plugins.azurekeyvaultplugin;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@WithJenkinsConfiguredWithCode
class ConfigAsCodeTest {

    @Test
    @ConfiguredWithCode("global-config.yml")
    void should_support_configuration_as_code(JenkinsConfiguredWithCodeRule j) {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();

        assertEquals("https://not-a-real-vault.vault.azure.net", globalConfiguration.getKeyVaultURL());
        assertEquals("service-principal", globalConfiguration.getCredentialID());
    }

    @Test
    @ConfiguredWithCode("global-config.yml")
    void export_configuration(JenkinsConfiguredWithCodeRule j) throws Exception {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();

        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        final Configurator<AzureKeyVaultGlobalConfiguration> c = context.lookupOrFail(AzureKeyVaultGlobalConfiguration.class);

        CNode node = c.describe(globalConfiguration, context);
        assertNotNull(node);
        final Mapping mapping = node.asMapping();

        assertEquals("https://not-a-real-vault.vault.azure.net", mapping.getScalarValue("keyVaultURL"));
        assertEquals("service-principal", mapping.getScalarValue("credentialID"));
    }
}

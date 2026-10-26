package org.jenkinsci.plugins.azurekeyvaultplugin;

import hudson.ExtensionList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Boots a real Jenkins <em>without</em> the optional {@code github-branch-source} plugin and asserts the
 * credentials provider still loads.
 *
 * <p>{@code GitHubAppCredentials} comes from that plugin. If any always-loaded class (e.g. the
 * {@code @Extension} {@link AzureCredentialsProvider}) referenced it at compile time, the provider would
 * fail to register with a {@code NoClassDefFoundError} when the plugin is absent, silently dropping every
 * Azure credential. Ordinary {@code @WithJenkins} tests cannot catch this because the plugin is always on
 * their classpath; {@link RealJenkinsExtension#omitPlugins} removes it from this instance.
 */
class OptionalPluginIsolationTest {

    @RegisterExtension
    private final RealJenkinsExtension rjr = new RealJenkinsExtension().omitPlugins("github-branch-source");

    @Test
    void providerLoadsWhenOptionalPluginAbsent() throws Throwable {
        rjr.then(OptionalPluginIsolationTest::assertProviderRegistered);
    }

    private static void assertProviderRegistered(JenkinsRule r) {
        // lookupSingleton fails if AzureCredentialsProvider did not register, which is exactly what
        // happens if it (or a class it references) fails to load without github-branch-source present.
        assertThat(ExtensionList.lookupSingleton(AzureCredentialsProvider.class), notNullValue());
    }
}

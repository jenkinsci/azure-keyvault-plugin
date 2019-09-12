package org.jenkinsci.plugins.azurekeyvaultplugin;

import hudson.EnvVars;
import java.io.IOException;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;

public class AzureKeyVaultEnvironmentExpander extends EnvironmentExpander {

    private final Map<String, String> secrets;

    AzureKeyVaultEnvironmentExpander(Map<String, String> secrets) {
        this.secrets = secrets;
    }

    @Override
    public void expand(@Nonnull EnvVars env) throws IOException, InterruptedException {
        env.overrideAll(secrets);
    }
}

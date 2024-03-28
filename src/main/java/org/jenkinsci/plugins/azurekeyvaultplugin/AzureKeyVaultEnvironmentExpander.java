package org.jenkinsci.plugins.azurekeyvaultplugin;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;

public class AzureKeyVaultEnvironmentExpander extends EnvironmentExpander {

    private final Map<String, String> secrets;

    AzureKeyVaultEnvironmentExpander(Map<String, String> secrets) {
        this.secrets = secrets;
    }

    @Override
    public void expand(@NonNull EnvVars env) throws IOException, InterruptedException {
        env.overrideAll(secrets);
    }

    @NonNull
    @Override
    public Set<String> getSensitiveVariables() {
        return secrets.keySet();
    }
}

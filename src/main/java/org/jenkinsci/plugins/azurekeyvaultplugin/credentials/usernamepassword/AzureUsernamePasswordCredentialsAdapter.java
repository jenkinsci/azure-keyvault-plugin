package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;

@Extension
@SuppressWarnings("unused")
public class AzureUsernamePasswordCredentialsAdapter extends AzureKeyVaultCredentialsAdapter {
    @NonNull
    @Override
    public String getType() {
        return "username";
    }

    @Override
    public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) {
        return new AzureUsernamePasswordCredentials(
                context.getScope(), context.getId(), context.getTag("username"), context.getDescription(), context.getSecret()
        );
    }
}

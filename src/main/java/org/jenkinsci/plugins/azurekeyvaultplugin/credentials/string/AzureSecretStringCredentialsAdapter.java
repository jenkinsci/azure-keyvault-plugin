package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;

@Extension
@SuppressWarnings("unused")
public class AzureSecretStringCredentialsAdapter extends AzureKeyVaultCredentialsAdapter {
    @NonNull
    @Override
    public String getType() {
        return "string";
    }

    @Override
    public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) {
        return new AzureSecretStringCredentials(context.getScope(), context.getId(), context.getDescription(), context.getSecret());
    }
}

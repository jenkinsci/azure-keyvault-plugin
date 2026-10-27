package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;

@Extension
@SuppressWarnings("unused")
public class AzureSecretFileCredentialsAdapter extends AzureKeyVaultCredentialsAdapter {
    @NonNull
    @Override
    public String getType() {
        return "secretFile";
    }

    @Override
    public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) {
        String fileName = context.getTag("fileName");
        if (StringUtils.isBlank(fileName)) {
            fileName = context.getSecretName() + ".txt";
        }
        return new AzureSecretFileCredentials(context.getScope(), context.getId(), context.getDescription(), fileName, context.getSecret());
    }
}

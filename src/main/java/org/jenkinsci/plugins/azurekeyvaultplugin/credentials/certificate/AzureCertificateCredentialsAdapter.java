package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.certificate;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;

@Extension
@SuppressWarnings("unused")
public class AzureCertificateCredentialsAdapter extends AzureKeyVaultCredentialsAdapter {
    @NonNull
    @Override
    public String getType() {
        return "certificate";
    }

    @Override
    public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) {
        String passwordId = context.getTag("password-id");
        Supplier<Secret> password = () -> Secret.fromString("");
        if (StringUtils.isNotBlank(passwordId)) {
            password = context.getSecret(passwordId);
        }
        return new AzureCertificateCredentials(context.getScope(), context.getId(), context.getDescription(), password, context.getSecret());
    }
}

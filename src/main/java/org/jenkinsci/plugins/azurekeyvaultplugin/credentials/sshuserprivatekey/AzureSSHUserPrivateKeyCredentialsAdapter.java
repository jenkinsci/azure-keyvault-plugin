package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.sshuserprivatekey;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;

@Extension
@SuppressWarnings("unused")
public class AzureSSHUserPrivateKeyCredentialsAdapter extends AzureKeyVaultCredentialsAdapter {
    private static final Logger LOG = Logger.getLogger(AzureSSHUserPrivateKeyCredentialsAdapter.class.getName());

    @NonNull
    @Override
    public String getType() {
        return "sshUserPrivateKey";
    }

    @Override
    public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) {
        String usernameSecretTag = context.getTag("username-is-secret");
        String passphraseID = context.getTag("passphrase-id");
        Secret passphrase = null;
        boolean usernameSecret = false;
        if (StringUtils.isNotBlank(usernameSecretTag)) {
            usernameSecret = Boolean.parseBoolean(usernameSecretTag);
        }
        if (StringUtils.isNotBlank(passphraseID)) {
            try {
                passphrase = context.getSecret(passphraseID).get();
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Could not find passphrase with ID " + passphraseID + " in KeyVault.");
                return null;
            }
        }
        return new AzureSSHUserPrivateKeyCredentials(
                context.getScope(), context.getId(), context.getDescription(), context.getTag("username"), usernameSecret, passphrase, context.getSecret()
        );
    }
}

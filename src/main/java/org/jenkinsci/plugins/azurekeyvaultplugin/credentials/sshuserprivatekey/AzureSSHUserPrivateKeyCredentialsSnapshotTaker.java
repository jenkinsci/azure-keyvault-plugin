package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.sshuserprivatekey;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class AzureSSHUserPrivateKeyCredentialsSnapshotTaker extends CredentialsSnapshotTaker<AzureSSHUserPrivateKeyCredentials> {
    @Override
    public Class<AzureSSHUserPrivateKeyCredentials> type() {
        return AzureSSHUserPrivateKeyCredentials.class;
    }

    @Override
    public AzureSSHUserPrivateKeyCredentials snapshot(AzureSSHUserPrivateKeyCredentials credential) {
        SecretSnapshot secretSnapshot = new SecretSnapshot(credential.getSecretValue());
        return new AzureSSHUserPrivateKeyCredentials(
                credential.getId(),
                credential.getDescription(),
                credential.getUsername(),
                credential.isUsernameSecret(),
                credential.getPassphrase(),
                secretSnapshot
        );
    }

    private static class SecretSnapshot extends Snapshot<Secret> {
        SecretSnapshot(Secret value) {
            super(value);
        }
    }
}

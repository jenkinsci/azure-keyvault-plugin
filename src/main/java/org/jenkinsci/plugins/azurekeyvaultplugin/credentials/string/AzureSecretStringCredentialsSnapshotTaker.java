package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class AzureSecretStringCredentialsSnapshotTaker extends CredentialsSnapshotTaker<AzureSecretStringCredentials> {
    @Override
    public Class<AzureSecretStringCredentials> type() {
        return AzureSecretStringCredentials.class;
    }

    @Override
    public AzureSecretStringCredentials snapshot(AzureSecretStringCredentials credential) {
        SecretSnapshot secretSnapshot = new SecretSnapshot(credential.getSecret());
        return new AzureSecretStringCredentials(credential.getId(), credential.getDescription(), secretSnapshot);
    }

    private static class SecretSnapshot extends Snapshot<Secret> {
        SecretSnapshot(Secret value) {
            super(value);
        }
    }
}

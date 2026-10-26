package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class AzureSecretFileCredentialsSnapshotTaker extends CredentialsSnapshotTaker<AzureSecretFileCredentials> {
    @Override
    public Class<AzureSecretFileCredentials> type() {
        return AzureSecretFileCredentials.class;
    }

    @Override
    public AzureSecretFileCredentials snapshot(AzureSecretFileCredentials credential) {
        SecretSnapshot secretSnapshot = new SecretSnapshot(credential.getSecretBytes());
        return new AzureSecretFileCredentials(
            credential.getScope(),
            credential.getId(),
            credential.getDescription(),
            credential.getFileName(),
            secretSnapshot
        );
    }

    private static class SecretSnapshot extends Snapshot<Secret> {
        SecretSnapshot(Secret value) {
            super(value);
        }
    }
}

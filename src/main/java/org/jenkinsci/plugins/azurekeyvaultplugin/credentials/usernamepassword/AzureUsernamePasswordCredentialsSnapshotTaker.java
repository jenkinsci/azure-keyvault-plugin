package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class AzureUsernamePasswordCredentialsSnapshotTaker extends CredentialsSnapshotTaker<AzureUsernamePasswordCredentials> {
    @Override
    public Class<AzureUsernamePasswordCredentials> type() {
        return AzureUsernamePasswordCredentials.class;
    }

    @Override
    public AzureUsernamePasswordCredentials snapshot(AzureUsernamePasswordCredentials credential) {
        SecretSnapshot secretSnapshot = new SecretSnapshot(credential.getPassword());
        return new AzureUsernamePasswordCredentials(credential.getScope(), credential.getId(), credential.getUsername(), credential.getDescription(), secretSnapshot);
    }

    private static class SecretSnapshot extends Snapshot<Secret> {
        SecretSnapshot(Secret value) {
            super(value);
        }
    }
}

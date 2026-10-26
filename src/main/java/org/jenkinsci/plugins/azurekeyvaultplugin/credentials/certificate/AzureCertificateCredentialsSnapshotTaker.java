package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.certificate;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class AzureCertificateCredentialsSnapshotTaker extends CredentialsSnapshotTaker<AzureCertificateCredentials> {
    @Override
    public Class<AzureCertificateCredentials> type() {
        return AzureCertificateCredentials.class;
    }

    @Override
    public AzureCertificateCredentials snapshot(AzureCertificateCredentials credential) {
        SecretSnapshot keyStoreSnapshot = new SecretSnapshot(credential.getKeyStoreSecret());
        SecretSnapshot passwordSnapshot = new SecretSnapshot(credential.getPassword());
        return new AzureCertificateCredentials(
            credential.getScope(),
            credential.getId(),
            credential.getDescription(),
            passwordSnapshot,
            keyStoreSnapshot
        );
    }

    private static class SecretSnapshot extends Snapshot<Secret> {
        SecretSnapshot(Secret value) {
            super(value);
        }
    }
}

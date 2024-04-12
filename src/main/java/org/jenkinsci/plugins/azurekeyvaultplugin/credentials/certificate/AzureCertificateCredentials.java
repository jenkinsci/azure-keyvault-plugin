package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.certificate;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.impl.Messages;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureCredentialsProvider;
import org.jvnet.localizer.ResourceBundleHolder;

public class AzureCertificateCredentials extends BaseStandardCredentials implements StandardCertificateCredentials {
    private static final Logger LOG = Logger.getLogger(AzureCertificateCredentials.class.getName());

    private final Supplier<Secret> keyStoreSource;
    private final Supplier<Secret> password;

    public AzureCertificateCredentials(
        CredentialsScope scope,
        String id,
        String description,
        Supplier<Secret> password,
        Supplier<Secret> keyStoreSource
    ) {
        super(scope, id, description);

        Objects.requireNonNull(keyStoreSource);
        this.password = password;
        this.keyStoreSource = keyStoreSource;
    }

    /**
     * Helper to convert a {@link Secret} password into a {@code char[]}
     *
     * @param password the password.
     * @return a {@code char[]} containing the password or {@code null}
     */
    @CheckForNull
    private static char[] toCharArray(@NonNull Secret password) {
        String plainText = Util.fixEmpty(password.getPlainText());
        return plainText == null ? null : plainText.toCharArray();
    }

    @NonNull
    @Override
    public KeyStore getKeyStore()
    {
        KeyStore keyStore;

        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (java.security.KeyStoreException e) {
            throw new IllegalStateException("PKCS12 is a keystore type per the JLS spec", e);
        }

        ByteArrayInputStream keyStoreByteInputStream;

        try{
            keyStoreByteInputStream = new ByteArrayInputStream(
                Base64.getDecoder().decode(
                    Secret.toString(keyStoreSource.get())
                )
            );
        } catch (java.lang.IllegalArgumentException e) {
            LOG.log(Level.WARNING, "Error decoding Keystore. A base64 encoded certificate is expected. Secret ID:" + getId() + ". " + e.getMessage(), e);
            throw new IllegalStateException("Cannot decode keystore", e);
        }


        try {
            keyStore.load(keyStoreByteInputStream, toCharArray(getPassword()));
        }
        catch(
            java.security.cert.CertificateException |
            java.security.NoSuchAlgorithmException |
            java.io.IOException e
        ){
            LOG.log(Level.WARNING, "Error loading Keystore . Secret ID:" + getId() + ". " + e.getMessage(), e);
            throw new IllegalStateException("Error loading Keystore.", e);
        }
        return keyStore;
    }

    @NonNull
    public Secret getKeyStoreSecret() {
        return keyStoreSource.get();
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return password.get();
    }


    @Extension
    @SuppressWarnings("unused")
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return ResourceBundleHolder.get(Messages.class).format("CertificateCredentialsImpl.DisplayName");
        }

        @Override
        public String getIconClassName() {
            return "icon-application-certificate";
        }

        @Override
        public boolean isApplicable(CredentialsProvider provider) {
            return provider instanceof AzureCredentialsProvider;
        }
    }
}

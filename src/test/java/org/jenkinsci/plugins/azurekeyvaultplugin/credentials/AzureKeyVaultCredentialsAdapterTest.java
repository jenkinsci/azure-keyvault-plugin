package org.jenkinsci.plugins.azurekeyvaultplugin.credentials;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import java.util.HashMap;
import java.util.Map;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.certificate.AzureCertificateCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile.AzureSecretFileCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

@WithJenkins
class AzureKeyVaultCredentialsAdapterTest {

    private static AzureKeyVaultSecretContext context(String... kv) {
        Map<String, String> tags = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            tags.put(kv[i], kv[i + 1]);
        }
        return new AzureKeyVaultSecretContext(
                CredentialsScope.GLOBAL, "my-id", "desc", "my-secret", tags,
                () -> Secret.fromString("value"),
                name -> () -> Secret.fromString("referenced-" + name));
    }

    private static IdCredentials adapt(String type, String... kv) throws Exception {
        return AzureKeyVaultCredentialsAdapter.forType(type).adapt(context(kv));
    }

    @Test
    void unknownType(JenkinsRule j) {
        assertThat(AzureKeyVaultCredentialsAdapter.forType("nope"), nullValue());
    }

    @Test
    void string(JenkinsRule j) throws Exception {
        IdCredentials cred = adapt("string");
        assertThat(cred, instanceOf(AzureSecretStringCredentials.class));
        assertThat(cred.getId(), is("my-id"));
        assertThat(((AzureSecretStringCredentials) cred).getSecret().getPlainText(), is("value"));
    }

    @Test
    void secretFile(JenkinsRule j) throws Exception {
        assertThat(((FileCredentials) adapt("secretFile", "fileName", "foo.txt")).getFileName(), is("foo.txt"));
        // previously threw a NullPointerException when the fileName tag was missing
        assertThat(((AzureSecretFileCredentials) adapt("secretFile")).getFileName(), is("my-secret.txt"));
    }

    @Test
    void username(JenkinsRule j) throws Exception {
        StandardUsernamePasswordCredentials cred = (StandardUsernamePasswordCredentials) adapt("username", "username", "bob");
        assertThat(cred.getUsername(), is("bob"));
        assertThat(cred.getPassword().getPlainText(), is("value"));
    }

    @Test
    void sshUserPrivateKey(JenkinsRule j) throws Exception {
        SSHUserPrivateKey cred = (SSHUserPrivateKey) adapt("sshUserPrivateKey",
                "username", "bob", "username-is-secret", "true", "passphrase-id", "pass");
        assertThat(cred.getUsername(), is("bob"));
        assertThat(cred.isUsernameSecret(), is(true));
        assertThat(cred.getPassphrase().getPlainText(), is("referenced-pass"));
        assertThat(cred.getPrivateKey(), is("value\n"));
    }

    @Test
    void certificate(JenkinsRule j) throws Exception {
        StandardCertificateCredentials cred = (StandardCertificateCredentials) adapt("certificate", "password-id", "pw");
        assertThat(cred, instanceOf(AzureCertificateCredentials.class));
        assertThat(cred.getPassword().getPlainText(), is("referenced-pw"));
        assertThat(((StandardCertificateCredentials) adapt("certificate")).getPassword().getPlainText(), is(""));
    }

    @Test
    void adapterFromAnotherPlugin(JenkinsRule j) throws Exception {
        IdCredentials cred = adapt("custom", "username", "alice");
        assertThat(cred, instanceOf(UsernamePasswordCredentialsImpl.class));
        assertThat(((UsernamePasswordCredentialsImpl) cred).getUsername(), is("alice"));
    }

    @TestExtension("adapterFromAnotherPlugin")
    public static class CustomAdapter extends AzureKeyVaultCredentialsAdapter {
        @NonNull
        @Override
        public String getType() {
            return "custom";
        }

        @Override
        public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) throws Exception {
            return new UsernamePasswordCredentialsImpl(
                    context.getScope(), context.getId(), context.getDescription(), context.getTag("username"),
                    context.getSecret().get().getPlainText());
        }
    }
}

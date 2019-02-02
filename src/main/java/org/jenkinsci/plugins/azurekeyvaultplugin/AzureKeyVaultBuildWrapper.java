/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.util.AzureCredentials;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildWrapper;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.tasks.SimpleBuildWrapper;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.security.auth.login.CredentialException;
import javax.security.auth.login.CredentialNotFoundException;
import javax.xml.bind.DatatypeConverter;

/**
 * Wraps a build with azure key vault secrets / certificates
 *
 * @author Kohsuke Kawaguchi
 */
public class AzureKeyVaultBuildWrapper extends SimpleBuildWrapper {

    private List<AzureKeyVaultSecret> azureKeyVaultSecrets;
    private static char[] emptyCharArray = new char[0];
    private static final Logger LOGGER = Logger.getLogger("Jenkins.AzureKeyVaultBuildWrapper");
    private List<String> valuesToMask = new ArrayList<>();
    
    // Instances for this particular build job, 
    // so they can override the global settings
    private String keyVaultURL;
    private String applicationID;
    private Secret applicationSecret;
    private String credentialID;
    
    @DataBoundConstructor
    public AzureKeyVaultBuildWrapper(@CheckForNull List<AzureKeyVaultSecret> azureKeyVaultSecrets) {
        this.azureKeyVaultSecrets = azureKeyVaultSecrets;
    }
    
    // Override KeyVault URL
    public String getKeyVaultURLOverride() {
        return this.keyVaultURL;
    }
    
    @DataBoundSetter
    public void setKeyVaultURLOverride(String keyVaultURL) {
        this.keyVaultURL = keyVaultURL;
    }
    
    // Override KeyVault Application ID
    public String getApplicationIDOverride() {
        return this.applicationID;
    }
    
    @DataBoundSetter
    public void setApplicationIDOverride(String applicationID) {
        this.applicationID = applicationID;
    }
    
    // Override Application Secret
    public Secret getApplicationSecretOverride() {
        return this.applicationSecret;
    }
    
    @DataBoundSetter
    public void setApplicationSecretOverride(String applicationSecret) {
        this.applicationSecret = Secret.fromString(applicationSecret);
    }
    
    // Override Application Secret ID
    public String getCredentialIDOverride() {
        return this.credentialID;
    }
    
    @DataBoundSetter
    public void setCredentialIDOverride(String credentialID) {
        this.credentialID = credentialID;
    }
    
    // Get the default value only if it is not overridden for this build
    public String getKeyVaultURL() {
        if (StringUtils.isNotEmpty(keyVaultURL)) {
            return keyVaultURL;
        }
        if (StringUtils.isNotEmpty(this.getDescriptor().getKeyVaultURL())) {
            return this.getDescriptor().getKeyVaultURL();
        } else {
            throw new AzureKeyVaultException("No key vault url configured, set one globally or in the build wrap step");
        }
    }

    @Override
    public ConsoleLogFilter createLoggerDecorator(@Nonnull final Run<?, ?> build) {
        return new MaskingConsoleLogFilter(build.getCharset().name(), valuesToMask);
    }
    
    
    public AzureKeyVaultCredential getKeyVaultCredential(Run<?, ?> build) throws CredentialException
    {
        // Try override values
        LOGGER.log(Level.FINE, "Trying override credentials...");
        AzureKeyVaultCredential credential = getKeyVaultCredential(build, this.applicationSecret, this.credentialID);
        if (credential.isValid()) {
            LOGGER.log(Level.FINE, "Using override credentials");
            return credential;
        }
        
        // Try global values
        LOGGER.log(Level.FINE, "Trying global credentials");
        credential = getKeyVaultCredential(build, null, getDescriptor().getCredentialID());
        if (credential.isValid()) {
            LOGGER.log(Level.FINE, "Using global credentials");
            return credential;
        }
        throw new CredentialNotFoundException("Unable to find a valid credential with provided parameters");
    }
       
    public AzureKeyVaultCredential getKeyVaultCredential(Run<?, ?> build, Secret applicationSecret, String credentialID)
        throws CredentialException {
        if (StringUtils.isNotEmpty(credentialID)) {
            LOGGER.log(Level.FINE, "Fetching credentials by ID");
            AzureKeyVaultCredential credential = getCredentialById(credentialID, build);
            if (!credential.isApplicationIDValid()) {
                LOGGER.log(Level.FINE, "Credential is password-only. Setting the username");
                // Credential only contains the app secret - add the app id
                credential.setApplicationID(getApplicationID());
            }
            return credential;
        }
        
        // Try AppID/Secret
        if (AzureKeyVaultUtil.isNotEmpty(applicationSecret)) {
            // Allowed in pipeline, but not global  config
            LOGGER.log(Level.FINE, "Using explicit application secret.");
            return new AzureKeyVaultCredential(getApplicationID(), applicationSecret);
        }
        
        return new AzureKeyVaultCredential();
    }
       
    public String getApplicationID() {
        if (StringUtils.isNotEmpty(applicationID)) {
            LOGGER.log(Level.FINE, "Using override Application ID");
            return applicationID;
        }
        return null;
    }
    
    public AzureKeyVaultCredential getCredentialById(String credentialID, Run<?, ?> build) throws CredentialException
    {
        AzureKeyVaultCredential credential = new AzureKeyVaultCredential();
        IdCredentials cred = CredentialsProvider.findCredentialById(credentialID, IdCredentials.class, build);
        
        if (cred==null)
        {
            throw new CredentialNotFoundException(credentialID);
        }
        
        if(StringCredentials.class.isInstance(cred))
        {
            // Secret Text object
            LOGGER.log(Level.FINE, String.format("Fetched %s as StringCredentials", credentialID));
            CredentialsProvider.track(build, cred);
            credential.setApplicationSecret(StringCredentials.class.cast(cred).getSecret());
            return credential;
        }
        else if(StandardUsernamePasswordCredentials.class.isInstance(cred))
        {
            // Username/Password Object
            LOGGER.log(Level.FINE, String.format("Fetched %s as StandardUsernamePasswordCredentials", credentialID));
            CredentialsProvider.track(build, cred);
            credential.setApplicationID(StandardUsernamePasswordCredentials.class.cast(cred).getUsername());
            credential.setApplicationSecret(StandardUsernamePasswordCredentials.class.cast(cred).getPassword());
            return credential;
        }
        else if (AzureCredentials.class.isInstance(cred)) {
            LOGGER.log(Level.FINE, String.format("Fetched %s as AzureCredentials", credentialID));
            CredentialsProvider.track(build, cred);
            AzureCredentials azureCredentials = (AzureCredentials) cred;

            credential.setApplicationID(azureCredentials.getClientId());
            credential.setApplicationSecret(azureCredentials.getPlainClientSecret());
            return credential;
        }
        else
        {
            throw new CredentialException("Could not determine the type for Secret id "
                    + credentialID +
                    " only 'Secret Text', 'Username/Password', and 'Microsoft Azure Service Principal' are supported");
        }
    }
    
    public List<AzureKeyVaultSecret> getAzureKeyVaultSecrets() {
        return azureKeyVaultSecrets;
    }
    
    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    private SecretBundle getSecret(KeyVaultClient client, AzureKeyVaultSecret secret) {
        try {
            return client.getSecret(getKeyVaultURL(), secret.getName(), secret.getVersion());
        } catch (Exception e) {
            throw new AzureKeyVaultException(e.getMessage(), e);
        }
    }
        
    public void setUp(Context context, Run<?, ?> build, FilePath workspace,
      Launcher launcher, TaskListener listener, EnvVars initialEnvironment) {
        if (azureKeyVaultSecrets == null || azureKeyVaultSecrets.isEmpty()) {
            return;
        }

        AzureKeyVaultCredential creds;
        try {
            creds = getKeyVaultCredential(build);
        }
        catch (CredentialException ex) {
            throw new AzureKeyVaultException(ex.getMessage(), ex);
        }
        if (creds == null || !creds.isValid()) {
            throw new AzureKeyVaultException("No valid credentials were found for accessing KeyVault");
        }
        KeyVaultClient client = new KeyVaultClient(creds);

        for (AzureKeyVaultSecret secret : azureKeyVaultSecrets) {
            if (secret.isPassword()) {
                SecretBundle bundle = getSecret(client, secret);
                if (bundle != null) {
                    valuesToMask.add(bundle.value());
                    context.env(secret.getEnvVariable(), bundle.value());
                } else {
                    throw new AzureKeyVaultException(String.format("Secret: %s not found", secret.getName()));
                }
            } else if (secret.isCertificate()) {
                // Get Certificate from Keyvault as a Secret
                SecretBundle bundle = getSecret(client, secret);
                if (bundle == null) {
                    continue;
                }
                try {
                    // Base64 decode the result and use a keystore to parse the key/cert
                    byte[] bytes = DatatypeConverter.parseBase64Binary(bundle.value());
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    ks.load(new ByteArrayInputStream(bytes), emptyCharArray);
                    
                    // Extract the key(s) and cert(s) and save them in a *second* keystore
                    // because the first keystore yields a corrupted PFX when written to disk
                    KeyStore ks2 = KeyStore.getInstance("PKCS12");
                    ks2.load(null, null);
                    
                    for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();)
                    {
                        String alias = e.nextElement();
                        Certificate[] chain = ks.getCertificateChain(alias);
                        Key privateKey = ks.getKey(alias, emptyCharArray);
                        ks2.setKeyEntry(alias, privateKey, emptyCharArray, chain);
                    }
                    
                    // Write PFX to disk on executor, which may be a separate physical system
                    FilePath outFile = workspace.createTempFile("keyvault", "pfx");
                    OutputStream outFileStream = outFile.write();
                    ks2.store(outFileStream, emptyCharArray);
                    outFileStream.close();
                    URI uri = outFile.toURI();
                    valuesToMask.add(uri.getPath());
                    context.env(secret.getEnvVariable(), uri.getPath());
                    
                } catch (Exception e) {
                    throw new AzureKeyVaultException(e.getMessage(), e);
                }
            }
        }
    }
    
    /**
     * Descriptor for {@link AzureKeyVaultBuildWrapper}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends Descriptor<BuildWrapper> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use {@code transient}.
         */
        private String keyVaultURL;
        private String credentialID;

        /**
         * In order to load the persisted global configuration, you have to 
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            super(AzureKeyVaultBuildWrapper.class);
            load();
        }

        public ListBoxModel doFillCredentialIDItems(@AncestorInPath Item item) {
            return new StandardListBoxModel().includeEmptyValue()
                    .includeAs(ACL.SYSTEM, item, StandardCredentials.class);
        }

        public ListBoxModel doFillCredentialIDOverrideItems(@AncestorInPath Item item) {
            return new StandardListBoxModel().includeEmptyValue()
                    .includeAs(ACL.SYSTEM, item, StandardCredentials.class);
        }

        public boolean isApplicable(AbstractProject<?, ? > item) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        public String getKeyVaultURL() {
            return keyVaultURL;
        }
        
        public void setKeyVaultUrl(String keyVaultURL) {
            this.keyVaultURL = keyVaultURL;
        }

        public String getCredentialID() {
            return credentialID;
        }
        
        public void setCredentialID(String credentialID) {
            this.credentialID = credentialID;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Azure Key Vault Plugin";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject json) {
            req.bindJSON(this, json);
            save();
            return true;
        }
    }
}


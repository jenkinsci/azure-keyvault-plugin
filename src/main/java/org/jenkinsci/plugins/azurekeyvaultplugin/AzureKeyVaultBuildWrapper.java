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

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import hudson.*;
import hudson.model.*;
import hudson.tasks.BuildWrapper;
import hudson.util.Secret;
import jenkins.tasks.SimpleBuildWrapper;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.annotation.CheckForNull;
import javax.xml.bind.DatatypeConverter;
import javax.security.auth.login.CredentialException;
import javax.security.auth.login.CredentialNotFoundException;

/**
 * Sample {@link Builder}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked
 * and a new {@link AzureKeyVaultBuildWrapper} is created. The created
 * instance is persisted to the project configuration XML by using
 * XStream, so this allows you to use instance fields (like {@link #name})
 * to remember the configuration.
 *
 * <p>
 * When a build is performed, the {@link #perform} method will be invoked. 
 *
 * @author Kohsuke Kawaguchi
 */
public class AzureKeyVaultBuildWrapper extends SimpleBuildWrapper {

    private List<AzureKeyVaultSecret> azureKeyVaultSecrets;
    private static char[] emptyCharArray = new char[0];
    private static final Logger LOGGER = Logger.getLogger("Jenkins.AzureKeyVaultBuildWrapper");
    
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
    public void setApplicationSecretOverride(Secret applicationSecret) {
        this.applicationSecret = applicationSecret;
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
        return this.getDescriptor().getKeyVaultURL();
    }
    
    
    public AzureKeyVaultCredential getKeyVaultCredential(Run<?, ?> build) throws CredentialNotFoundException, CredentialException
    {
        // Try override values
        LOGGER.log(Level.INFO, String.format("Trying override credentials..."));
        AzureKeyVaultCredential credential = getKeyVaultCredential(build, this.applicationSecret, this.credentialID);
        if (credential.isValid())
        {
            LOGGER.log(Level.INFO, String.format("Using override credentials"));
            return credential;
        }
        
        // Try global values
        LOGGER.log(Level.INFO, String.format("Trying global credentials"));
        credential = getKeyVaultCredential(build, getDescriptor().getApplicationSecret(), getDescriptor().getCredentialID());
        if (credential.isValid())
        {
            LOGGER.log(Level.INFO, String.format("Using global credentials"));
            return credential;
        }
        throw new CredentialNotFoundException("Unable to find a valid credential with provided parameters");
    }
       
    public AzureKeyVaultCredential getKeyVaultCredential(Run<?, ?> build, Secret _applicationSecret, String _credentialID) 
        throws CredentialNotFoundException, CredentialException
    {
        // Try Credential
        if (StringUtils.isNotEmpty(_credentialID))
        {
            LOGGER.log(Level.INFO, "Fetching credentials by ID");
            AzureKeyVaultCredential credential = getCredentialById(_credentialID, build);
            if (!credential.isApplicationIDValid())
            {
                LOGGER.log(Level.INFO, "Credential is password-only. Setting the username");
                // Credential only contains the app secret - add the app id
                credential.setApplicationID(getApplicationID());
            }
            return credential;
        }
        
        // Try AppID/Secret
        if (AzureKeyVaultUtil.isNotEmpty(_applicationSecret))
        {
            LOGGER.log(Level.WARNING, String.format("Using explicit application secret. This will be deprecated in 1.0. Use Credential ID instead."));
            return new AzureKeyVaultCredential(getApplicationID(), _applicationSecret);
        }
        
        return new AzureKeyVaultCredential();
    }
       
    public String getApplicationID() {
        if (StringUtils.isNotEmpty(applicationID))
        {
            LOGGER.log(Level.INFO, String.format("Using override Application ID"));
            return applicationID;
        }
        LOGGER.log(Level.INFO, String.format("Using global Application ID"));
        return getDescriptor().getApplicationID();
    }
    
    public AzureKeyVaultCredential getCredentialById(String _credentialID, Run<?, ?> build) throws CredentialNotFoundException, CredentialException
    {
        AzureKeyVaultCredential credential = new AzureKeyVaultCredential();
        IdCredentials cred = CredentialsProvider.findCredentialById(_credentialID, IdCredentials.class, build);
        
        if (cred==null)
        {
            throw new CredentialNotFoundException(_credentialID);
        }
        
        if(StringCredentials.class.isInstance(cred))
        {
            // Secret Text object
            LOGGER.log(Level.INFO, String.format("Fetched %s as StringCredentials", _credentialID));
            CredentialsProvider.track(build, cred);
            credential.setApplicationSecret(StringCredentials.class.cast(cred).getSecret());
            return credential;
        }
        else if(StandardUsernamePasswordCredentials.class.isInstance(cred))
        {
            // Username/Password Object
            LOGGER.log(Level.INFO, String.format("Fetched %s as StandardUsernamePasswordCredentials", _credentialID));
            CredentialsProvider.track(build, cred);
            credential.setApplicationID(StandardUsernamePasswordCredentials.class.cast(cred).getUsername());
            credential.setApplicationSecret(StandardUsernamePasswordCredentials.class.cast(cred).getPassword());
            return credential;
        }
        else
        {
            throw new CredentialException("Could not determine the type for Secret id " + _credentialID + " only 'Secret Text' and 'Username/Password' are supported");
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
            SecretBundle bundle = client.getSecret(getKeyVaultURL(), secret.getName(), secret.getVersion());
            return bundle;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, e.toString(), e);
        }
        return null;
    }
        
    public void setUp(Context context, Run<?, ?> build, FilePath workspace,
      Launcher launcher, TaskListener listener, EnvVars initialEnvironment) {           
        AzureKeyVaultCredential creds;
        try
        {
            creds = getKeyVaultCredential(build);
        }
        catch (CredentialException ex)
        {
            LOGGER.log(Level.SEVERE, ex.toString(), ex);
            return;
        }
        if (creds == null || !creds.isValid())
        {
            LOGGER.log(Level.SEVERE, "No valid credentials were found for accessing KeyVault");
            return;
        }
        KeyVaultClient client = new KeyVaultClient(creds);

        for (AzureKeyVaultSecret secret : azureKeyVaultSecrets) {
            if (secret.isPassword()) {
                SecretBundle bundle = getSecret(client, secret);
                if (bundle != null) {
                    context.env(secret.getEnvVariable(), bundle.value());
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
                    context.env(secret.getEnvVariable(), uri.getPath());
                    
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, e.toString(), e);
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
        private String applicationID;
        private Secret applicationSecret;
        private String credentialID;

        /**
         * In order to load the persisted global configuration, you have to 
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            super(AzureKeyVaultBuildWrapper.class);
            load();
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

        public String getApplicationID() {
            return applicationID;
        }
        
        public void setApplicationID(String applicationID) {
            this.applicationID = applicationID;
        }

        public Secret getApplicationSecret() {
            return applicationSecret;
        }
        
        public void setApplicationSecret(String applicationSecret) {
            this.applicationSecret = Secret.fromString(applicationSecret);
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
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            this.keyVaultURL = formData.getString("keyVaultURL");
            this.applicationID = formData.getString("applicationID");
            this.applicationSecret = Secret.fromString(formData.getString("applicationSecret"));
            this.credentialID = formData.getString("credentialID");
            save();
            return super.configure(req,formData);
        }
    }
}


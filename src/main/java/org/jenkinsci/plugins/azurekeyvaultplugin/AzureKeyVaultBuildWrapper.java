package org.jenkinsci.plugins.azurekeyvaultplugin;
import hudson.*;
import hudson.model.*;
import hudson.tasks.BuildWrapper;
import hudson.util.Secret;
import jenkins.tasks.SimpleBuildWrapper;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.CheckForNull;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

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

    private String keyVaultURL;
    private String applicationID;
    private Secret applicationToken;
    private List<AzureKeyVaultSecretValue> azureKeyVaultSecretValues;

    @DataBoundConstructor
    public AzureKeyVaultBuildWrapper(@CheckForNull List<AzureKeyVaultSecretValue> azureKeyVaultSecretValues) {
        
        if (azureKeyVaultSecretValues == null)
        {
            System.out.println("Constructed AzureKeyVaultBuildWrapper with NULL");
            // throw new NullPointerException("Provided secret list is NULL");
            this.azureKeyVaultSecretValues = new ArrayList<AzureKeyVaultSecretValue>();
            this.azureKeyVaultSecretValues.add(secret);
        }
        else
        {
            System.out.format("Constructed AzureKeyVaultBuildWrapper with %d secrets %n", azureKeyVaultSecretValues.size());
            this.azureKeyVaultSecretValues = azureKeyVaultSecretValues;
        }
    }

    @DataBoundSetter
    public void setKeyVaultURL(String url) {
        keyVaultURL = url;
    }
    
    public String getKeyVaultURL() {
        return keyVaultURL;
    }
    
    @DataBoundSetter
    public void setApplicationID(String id) {
        applicationID = id;
    }
    
    public String getApplicationID() {
        return applicationID;
    }
    
    @DataBoundSetter
    public void setApplicationToken(Secret token) {
        applicationToken = token;
    }
    
    public Secret getApplicationToken() {
        return applicationToken;
    }
    
    public List<AzureKeyVaultSecretValue> getAzureKeyVaultSecretValues() {
        if (azureKeyVaultSecretValues == null)
        {
            azureKeyVaultSecretValues = new ArrayList<AzureKeyVaultSecretValue>();
            System.out.println("Attempt to GetList that is NULL");
        }
        else
        {
            System.out.format("GetList %d %n", azureKeyVaultSecretValues.size());
        }
        return azureKeyVaultSecretValues;
    }
    
    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    public void setUp(Context context, Run<?, ?> build, FilePath workspace,
      Launcher launcher, TaskListener listener, EnvVars initialEnvironment) {
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

        /**
         * In order to load the persisted global configuration, you have to 
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            super(AzureKeyVaultBuildWrapper.class);
            load();
        }

        // public boolean isApplicable(Class<? extends AbstractProject> aClass) {
        public boolean isApplicable(AbstractProject<?, ? > item) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        public String getKeyVaultURL() {
            return keyVaultURL;
        }
        
        public void setKeyVaultUrl(String url) {
            keyVaultURL = url;
        }

        public String getApplicationID() {
            return applicationID;
        }
        
        public void setApplicationID(String id) {
            applicationID = id;
        }

        public Secret getApplicationSecret() {
            return applicationSecret;
        }
        
        public void setApplicationSecret(String secret) {
            applicationSecret = Secret.fromString(secret);
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Azure Key Vault Plugin";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            keyVaultURL = formData.getString("KeyVaultURL");
            applicationID = formData.getString("ApplicationID");
            applicationSecret = Secret.fromString(formData.getString("ApplicationSecret"));
            save();
            return super.configure(req,formData);
        }
    }
}


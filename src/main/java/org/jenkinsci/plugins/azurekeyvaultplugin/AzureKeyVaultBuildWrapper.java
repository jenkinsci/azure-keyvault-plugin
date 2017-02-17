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
    private List<AzureKeyVaultSecret> keyVaultSecrets;

    @DataBoundConstructor
    public AzureKeyVaultBuildWrapper(@CheckForNull List<AzureKeyVaultSecret> secrets) {
        keyVaultSecrets = secrets;
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
    
    public List<AzureKeyVaultSecret> getKeyVaultSecrets() {
        return keyVaultSecrets;
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

        public String GetKeyVaultURL() {
            return keyVaultURL;
        }

        public String GetApplicationID() {
            return applicationID;
        }

        public Secret GetApplicationSecret() {
            return applicationSecret;
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


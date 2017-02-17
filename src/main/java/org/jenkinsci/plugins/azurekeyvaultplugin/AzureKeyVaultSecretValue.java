package org.jenkinsci.plugins.azurekeyvaultplugin;
import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

public class AzureKeyVaultSecretValue extends 
    AbstractDescribableImpl<AzureKeyVaultSecretValue>
{
    private String envVariable;
    private String name;
    private String version;

    @DataBoundConstructor
    public AzureKeyVaultSecretValue(String _envVariable, String _name,
        String _version)
    {
        envVariable = _envVariable;
        name = _name;
        version = _version;
    }
    
    public String getEnvVariable()
    {
        return envVariable;
    }
    
    public String getName()
    {
        return name;
    }
    
    public String getVersion()
    {
        return version;
    }
    
    @Extension
    public static final class DescriptorImpl extends Descriptor<AzureKeyVaultSecretValue>
    {
        @Override
        public String getDisplayName()
        {
            return "Environment variable, and name/version pair for an Azure Key Vault secret";
        }
    }
}
package org.jenkinsci.plugins.azurekeyvaultplugin;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

public class AzureKeyVaultSecretValue extends 
    AbstractDescribableImpl<AzureKeyVaultSecretValue>
{
    private String secretType;
    private String name;
    private String version;
    private String envVariable;

    @DataBoundConstructor
    public AzureKeyVaultSecretValue(String _secretType, String _name,
        String _version, String _envVariable)
    {
        secretType = _secretType;
        envVariable = _envVariable;
        name = _name;
        version = _version;
    }
    
    public String getSecretType()
    {
        return secretType;
    }
    
    @DataBoundSetter
    public void setSecretType(String _secretType)
    {
        secretType = _secretType;
    }
        
    public String getName()
    {
        return name;
    }
    
    @DataBoundSetter
    public void setName(String _name)
    {
        name = _name;
    }
    
    public String getVersion()
    {
        return version;
    }
    
    @DataBoundSetter
    public void setVersion(String _version)
    {
        version = _version;
    }
    
    public String getEnvVariable()
    {
        return envVariable;
    }
    
    @DataBoundSetter
    public void setEnvVariable(String _envVariable)
    {
        envVariable = _envVariable;
    }
    
    @Extension
    public static final class DescriptorImpl extends Descriptor<AzureKeyVaultSecretValue>
    {
        @Override
        public String getDisplayName()
        {
            return "Secret type, environment variable, and name/version pair for an Azure Key Vault secret";
        }
    }
}
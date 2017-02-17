package org.jenkinsci.plugins.azurekeyvaultplugin;

import java.util.List;

import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

public class AzureKeyVaultSecret extends AbstractDescribableImpl<AzureKeyVaultSecret>
{
    private String path;
    private List<AzureKeyVaultSecretValue> secretValues;
    
    @DataBoundConstructor
    public AzureKeyVaultSecret(String path, List<AzureKeyVaultSecretValue> secretValues)
    {
        this.path = path;
        this.secretValues = secretValues;
    }
    
    public String getPath()
    {
        return path;
    }
    
    public List<AzureKeyVaultSecretValue> getSecretValues()
    {
        return secretValues;
    }
    
    @Extension
    public static final class DescriptorImpl extends Descriptor<AzureKeyVaultSecret>
    {
        @Override
        public String getDisplayName()
        {
            return "Azure Key Vault Secret";
        }
    }
}
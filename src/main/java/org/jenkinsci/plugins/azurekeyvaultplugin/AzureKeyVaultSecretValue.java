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
/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2017 Microsoft Corporation
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.jenkinsci.plugins.azurekeyvaultplugin;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class AzureKeyVaultSecret extends
        AbstractDescribableImpl<AzureKeyVaultSecret> {
    public static final String typeSecret = "Secret";
    public static final String typeCertificate = "Certificate";
    private String secretType;
    private String name;
    private String version;
    private String envVariable;

    @DataBoundConstructor
    public AzureKeyVaultSecret(
            String secretType,
            String name,
            String version,
            String envVariable
    ) {
        this.secretType = secretType;
        this.name = name;
        this.version = version;
        this.envVariable = envVariable;
    }

    public String getSecretType() {
        return secretType;
    }

    @DataBoundSetter
    public void setSecretType(String secretType) {
        this.secretType = secretType;
    }

    public String getName() {
        return name;
    }

    @DataBoundSetter
    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    @DataBoundSetter
    public void setVersion(String version) {
        this.version = version;
    }

    public String getEnvVariable() {
        return envVariable;
    }

    @DataBoundSetter
    public void setEnvVariable(String envVariable) {
        this.envVariable = envVariable;
    }

    public boolean isPassword() {
        if (secretType == null || !secretType.equals(typeSecret)) {
            return false;
        }
        return true;
    }

    public boolean isCertificate() {
        if (secretType == null || !secretType.equals(typeCertificate)) {
            return false;
        }
        return true;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<AzureKeyVaultSecret> {
        @Override
        public String getDisplayName() {
            return "Secret type, environment variable, and name/version pair for an Azure Key Vault secret";
        }

        public ListBoxModel doFillSecretTypeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(typeSecret, typeSecret);
            items.add(typeCertificate, typeCertificate);
            return items;
        }
    }
}
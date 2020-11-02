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

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.azure.util.AzureImdsCredentials;
import hudson.FilePath;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;
import javax.xml.bind.DatatypeConverter;
import jenkins.model.Jenkins;

class AzureKeyVaultUtil {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];
    private static final String PKCS12 = "PKCS12";

    static String convertAndWritePfxToDisk(FilePath workspace, String secret)
            throws IOException, GeneralSecurityException, InterruptedException {
        // Base64 decode the result and use a keystore to parse the key/cert
        byte[] bytes = DatatypeConverter.parseBase64Binary(secret);
        KeyStore ks = KeyStore.getInstance(PKCS12);
        ks.load(new ByteArrayInputStream(bytes), EMPTY_CHAR_ARRAY);

        // Extract the key(s) and cert(s) and save them in a *second* keystore
        // because the first keystore yields a corrupted PFX when written to disk
        KeyStore ks2 = KeyStore.getInstance(PKCS12);
        ks2.load(null, null);

        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            Certificate[] chain = ks.getCertificateChain(alias);
            Key privateKey = ks.getKey(alias, EMPTY_CHAR_ARRAY);
            ks2.setKeyEntry(alias, privateKey, EMPTY_CHAR_ARRAY, chain);
        }

        // ensure workspace has been created
        workspace.mkdirs();

        // Write PFX to disk on executor, which may be a separate physical system
        FilePath outFile = workspace.createTempFile("keyvault-", ".pfx");
        try (OutputStream outFileStream = outFile.write()) {
            ks2.store(outFileStream, EMPTY_CHAR_ARRAY);
        }

        URI uri = outFile.toURI();
        return uri.getPath();
    }

    public static ListBoxModel doFillCredentialIDItems(Item context) {
        if (context == null && !Jenkins.get().hasPermission(Jenkins.ADMINISTER) ||
                context != null && !context.hasPermission(Item.CONFIGURE)) {
            return new StandardListBoxModel();
        }

        return new StandardListBoxModel().includeEmptyValue()
                .includeAs(ACL.SYSTEM, context, AzureImdsCredentials.class)
                .includeAs(ACL.SYSTEM, context, AzureCredentials.class);
    }
}

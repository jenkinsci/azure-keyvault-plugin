package org.jenkinsci.plugins.azurekeyvaultplugin.provider;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder.FolderAzureCredentialsProvider;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.global.AzureCredentialsProvider;

public class CredentialsProviderHelper {

    private CredentialsProviderHelper() {
    }

    public static boolean isAzureCredentialsProvider(CredentialsProvider provider) {
        return provider instanceof AzureCredentialsProvider || provider instanceof FolderAzureCredentialsProvider;
    }
}

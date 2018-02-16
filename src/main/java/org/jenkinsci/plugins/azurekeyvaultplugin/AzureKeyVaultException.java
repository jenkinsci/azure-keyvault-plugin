package org.jenkinsci.plugins.azurekeyvaultplugin;

public class AzureKeyVaultException extends RuntimeException {

    public AzureKeyVaultException(String message) {
        super(message);
    }

    public AzureKeyVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}

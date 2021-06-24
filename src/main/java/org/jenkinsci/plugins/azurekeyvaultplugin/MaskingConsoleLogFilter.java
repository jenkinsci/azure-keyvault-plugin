package org.jenkinsci.plugins.azurekeyvaultplugin;

import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.List;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;

public class MaskingConsoleLogFilter extends ConsoleLogFilter
        implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String charsetName;
    private final List<String> valuesToMask;


    public MaskingConsoleLogFilter(final String charsetName,
                                   final List<String> valuesToMask
    ) {
        this.charsetName = charsetName;
        this.valuesToMask = valuesToMask;
    }

    @Override
    public OutputStream decorateLogger(
            Run run,
            final OutputStream logger
    ) {
        return new SecretPatterns.MaskingOutputStream(logger, () -> SecretPatterns.getAggregateSecretPattern(valuesToMask), charsetName);
    }

}

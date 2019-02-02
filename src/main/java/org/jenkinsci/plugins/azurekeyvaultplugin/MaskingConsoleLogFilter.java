package org.jenkinsci.plugins.azurekeyvaultplugin;

import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.model.Run;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*The logic in this class is borrowed from https://github.com/jenkinsci/credentials-binding-plugin/*/
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
        return new LineTransformationOutputStream() {
            Pattern p;

            @Override
            protected void eol(byte[] b, int len) throws IOException {
                p = Pattern.compile(getPatternStringForSecrets(valuesToMask));
                if (StringUtils.isBlank(p.pattern())) {
                    logger.write(b, 0, len);
                    return;
                }
                Matcher m = p.matcher(new String(b, 0, len, charsetName));
                if (m.find()) {
                    logger.write(m.replaceAll("****").getBytes(charsetName));
                } else {
                    // Avoid byte → char → byte conversion unless we are actually doing something.
                    logger.write(b, 0, len);
                }
            }
        };
    }

    /**
     * Utility method for turning a collection of secret strings into a single {@link String} for pattern compilation.
     *
     * @param secrets A collection of secret strings
     * @return A {@link String} generated from that collection.
     */
    public static String getPatternStringForSecrets(Collection<String> secrets) {
        if (secrets == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        List<String> sortedByLength = new ArrayList<>(secrets.size());
        for (String secret : secrets) {
            if (secret != null) {
                sortedByLength.add(secret);
            }
        }
        sortedByLength.sort((o1, o2) -> o2.length() - o1.length());

        for (String secret : sortedByLength) {
            if (b.length() > 0) {
                b.append('|');
            }
            b.append(Pattern.quote(secret));
        }
        return b.toString();
    }


}
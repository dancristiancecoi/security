/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.hasher;

import java.nio.CharBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;

import com.password4j.BcryptFunction;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;
import org.opensearch.SpecialPermission;

public class BCryptPasswordHasher implements PasswordHasher {

    @Override
    public String hash(char[] password) {
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                    (PrivilegedAction<String>) () -> Password.hash(passwordBuffer).with(getBCryptFunction()).getResult()
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }

    @Override
    public boolean check(char[] password, String hash) {
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                    (PrivilegedAction<Boolean>) () -> Password.check(passwordBuffer, hash).with(getBCryptFunction())
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }

    private void cleanup(CharBuffer password) {
        password.clear();
        char[] passwordOverwrite = new char[password.capacity()];
        Arrays.fill(passwordOverwrite, '\0');
        password.put(passwordOverwrite);
    }

    private HashingFunction getBCryptFunction() {
        return BcryptFunction.getInstance(Bcrypt.Y, 12);
    }
}

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
import java.util.Arrays;

import com.password4j.BcryptFunction;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;

public class BCryptPasswordHasher implements PasswordHasher {

    @Override
    public String hash(CharBuffer password) {
        try {
            return Password.hash(password).with(getBCryptFunction()).getResult();
        } finally {
            cleanup(password);
        }
    }

    @Override
    public String hash(char[] password) {
        return hash(CharBuffer.wrap(password));
    }

    @Override
    public boolean check(CharBuffer password, String hash) {
        try {
            return Password.check(password, hash).with(getBCryptFunction());
        } finally {
            cleanup(password);
        }
    }

    @Override
    public boolean check(char[] password, String hash) {
        return check(CharBuffer.wrap(password), hash);
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

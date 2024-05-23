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

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {

    private final PasswordHasher passwordHasher = new PasswordHasherImpl();

    private final String password = "testPassword";

    @Test
    public void shouldMatchHashToCorrectPassword() {
        String hashedPassword = passwordHasher.hash(password.toCharArray());
        assertTrue(passwordHasher.check(password.toCharArray(), hashedPassword));
    }

    @Test
    public void shouldNotMatchHashToWrongPassword() {
        String hashedPassword = passwordHasher.hash(password.toCharArray());
        String wrongPassword = "wrongTestPassword";
        assertFalse(passwordHasher.check(wrongPassword.toCharArray(), hashedPassword));
    }

    @Test
    public void shouldCleanupPasswordCharArray() {
        char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        passwordHasher.hash(password);
        assertTrue(new String(password).equals("\0\0\0\0\0\0\0\0"));
    }

    @Test
    public void shouldCleanupPasswordCharBuffer() {
        char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        passwordHasher.hash(password);
        assertTrue(new String(password).equals("\0\0\0\0\0\0\0\0"));
        assertTrue(passwordBuffer.toString().equals("\0\0\0\0\0\0\0\0"));
    }
}

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

package org.opensearch.security;

import java.nio.CharBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import org.junit.Test;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.hash.PasswordHasher;
import org.opensearch.security.hash.PasswordHasherImpl;
import org.opensearch.security.support.ConfigConstants;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {

    final String password = "testPassword";
    final String wrongPassword = "wrongTestPassword";

    @Test
    public void testDefaultHash() {
        // should default to BCrypt
        final Settings settings = Settings.EMPTY;
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        String hashedPassword = passwordHasher.hash(CharBuffer.wrap(password.toCharArray()));
        assertTrue(passwordHasher.check(CharBuffer.wrap(password.toCharArray()), hashedPassword));
        assertFalse(passwordHasher.check(CharBuffer.wrap(wrongPassword.toCharArray()), hashedPassword));
    }

    @Test
    public void testLegacyHash() {
        final Settings settings = Settings.EMPTY;
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        String legacyHash = generateLegacyBCryptHash(password.toCharArray());
        assertTrue(passwordHasher.check(CharBuffer.wrap(password.toCharArray()), legacyHash));
        assertFalse(passwordHasher.check(CharBuffer.wrap(wrongPassword.toCharArray()), legacyHash));
    }

    @Test
    public void testPKDF2() {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "pbkdf2").build();
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        String hashedPassword = passwordHasher.hash(CharBuffer.wrap(password.toCharArray()));
        assertTrue(passwordHasher.check(CharBuffer.wrap(password.toCharArray()), hashedPassword));
        assertFalse(passwordHasher.check(CharBuffer.wrap(wrongPassword.toCharArray()), hashedPassword));
    }

    @Test
    public void testSCrypt() {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "scrypt").build();
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        String hashedPassword = passwordHasher.hash(CharBuffer.wrap(password.toCharArray()));
        assertTrue(passwordHasher.check(CharBuffer.wrap(password.toCharArray()), hashedPassword));
        assertFalse(passwordHasher.check(CharBuffer.wrap(wrongPassword.toCharArray()), hashedPassword));
    }

    @Test
    public void testArgon2() {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "argon2").build();
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        String hashedPassword = passwordHasher.hash(CharBuffer.wrap(password.toCharArray()));
        assertTrue(passwordHasher.check(CharBuffer.wrap(password.toCharArray()), hashedPassword));
        assertFalse(passwordHasher.check(CharBuffer.wrap(wrongPassword.toCharArray()), hashedPassword));
    }

    @Test
    public void testPasswordCleanup() {
        final Settings settings = Settings.EMPTY;
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        passwordHasher.hash(passwordBuffer);
        assertFalse(new String(password).contains("password"));
        assertFalse(passwordBuffer.toString().contains("password"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testWrongHashingAlgorithm() {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "unsupported").build();
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        passwordHasher.hash(CharBuffer.wrap(password.toCharArray()));
    }

    private String generateLegacyBCryptHash(final char[] clearTextPassword) {
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(clearTextPassword, '\0');
        return hash;
    }
}

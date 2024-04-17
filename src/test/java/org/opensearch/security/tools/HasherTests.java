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

package org.opensearch.security.tools;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.password4j.CompressedPBKDF2Function;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HasherTests {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    @Before
    public void setOutputStreams() {
        System.setOut(new PrintStream(out));
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setIn(originalIn);
    }

    @Test
    public void testWithDefaultArguments() {
        Hasher.main(new String[] { "-p", "password" });
        String hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the default BCrypt configuration", hash.startsWith("$2b$12"));
    }

    @Test
    public void testWithBCryptRoundsArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-r", "5" });
        String hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the correct value for \"rounds\"", hash.startsWith("$2b$05"));
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-r", "5" });
        hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the correct value for \"rounds\"", hash.startsWith("$2b$05"));
    }

    @Test
    public void testWithBCryptMinorArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "A" });
        String hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the correct value for \"minor\"", hash.startsWith("$2a$12"));
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "Y" });
        hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the correct value for \"minor\"", hash.startsWith("$2y$12"));
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "B" });
        hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the correct value for \"minor\"", hash.startsWith("$2b$12"));
        out.reset();
    }

    @Test
    public void testWithBCryptAllArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "A", "-r", "5" });
        String hash = getHashFromStdOut();
        assertTrue("should return a valid BCrypt hash with the correct configuration", hash.startsWith("$2a$05"));
    }

    @Test
    public void testWithPBKDF2DefaultArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2" });
        String hash = getHashFromStdOut();
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 310000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 512);
    }

    @Test
    public void testWithPBKDF2FunctionArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-f", "SHA512" });
        String hash = getHashFromStdOut();
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA512");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 310000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 512);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-f", "SHA384" });
        hash = getHashFromStdOut();
        pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA384");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 310000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 512);
    }

    @Test
    public void testWithPBKDF2IterationsArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-i", "100000" });
        String hash = getHashFromStdOut();
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 100000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 512);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-i", "200000" });
        hash = getHashFromStdOut();
        pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 200000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 512);
    }

    @Test
    public void testWithPBKDF2LengthArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-l", "400" });
        String hash = getHashFromStdOut();
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 310000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 400);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-l", "300" });
        hash = getHashFromStdOut();
        pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 310000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 300);
    }

    @Test
    public void testWithPBKDF2AllArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-l", "250", "-i", "150000", "-f", "SHA384" });
        String hash = getHashFromStdOut();
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(hash);
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA384");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 150000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 250);
    }

    @Test
    public void testWithSCryptDefaultArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "SCrypt" });
        String hash = getHashFromStdOut();
        assertEquals("should return a valid SCrypt hash with the correct value for \"derived key length\"", "a", "a");
    }

    private String getHashFromStdOut() {
        String[] splitOut = out.toString().split("\n");
        return splitOut[splitOut.length - 1];
    }

}

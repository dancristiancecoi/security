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

package org.opensearch.security.hash;

import java.nio.CharBuffer;
import java.util.Arrays;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import com.password4j.*;
import com.password4j.types.Argon2;
import com.password4j.types.Bcrypt;

import static org.opensearch.security.support.ConfigConstants.*;

public class PasswordHasherImpl implements PasswordHasher {

    private final Settings settings;

    public PasswordHasherImpl(Settings settings) {
        this.settings = settings;
    }

    public PasswordHasherImpl() {
        this(Settings.EMPTY);
    }

    @Override
    public String hash(CharBuffer password) {
        try {
            return Password.hash(password).with(getHashingFunction()).getResult();
        } finally {
            cleanup(password);
        }
    }

    @Override
    public boolean check(CharBuffer password, String hash) {
        try {
            return Password.check(password, hash).with(getHashingFunction());
        } finally {
            cleanup(password);
        }
    }

    private void cleanup(CharBuffer password) {
        password.clear();
        char[] passwordOverwrite = new char[password.capacity()];
        Arrays.fill(passwordOverwrite, '\0');
        password.put(passwordOverwrite);
    }

    private HashingFunction getHashingFunction() {

        String algorithm = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM_DEFAULT
        );

        HashingFunction hashingFunction;

        switch (algorithm.toLowerCase()) {
            case BCRYPT:
                hashingFunction = getBCryptFunction();
                break;
            case PBKDF2:
                hashingFunction = getPBKDF2Function();
                break;
            case SCRYPT:
                hashingFunction = getSCryptFunction();
                break;
            case ARGON2:
                hashingFunction = getArgon2Function();
                break;
            default:
                throw new OpenSearchSecurityException("Password hashing algorithm not supported");
        }
        return hashingFunction;
    }

    private HashingFunction getPBKDF2Function() {
        int iterations = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT
        );
        int length = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT
        );
        String pbkdf2Function = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT
        );

        return CompressedPBKDF2Function.getInstance(pbkdf2Function, iterations, length);
    }

    private HashingFunction getSCryptFunction() {
        int workFactor = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_WORK_FACTOR,
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_WORK_FACTOR_DEFAULT
        );
        int resources = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_RESOURCES,
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_RESOURCES_DEFAULT
        );
        int parallelization = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_PARALLELIZATION,
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_PARALLELIZATION_DEFAULT
        );
        int derivedKeyLength = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_DERIVED_KEY_LENGTH,
            ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_DERIVED_KEY_LENGTH_DEFAULT
        );
        return ScryptFunction.getInstance(workFactor, resources, parallelization, derivedKeyLength);
    }

    private HashingFunction getArgon2Function() {
        int memory = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY_DEFAULT
        );
        int iterations = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS_DEFAULT
        );
        int length = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH_DEFAULT
        );
        int parallelism = settings.getAsInt(
            SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM_DEFAULT
        );
        String type = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE_DEFAULT
        );
        int version = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION_DEFAULT
        );
        return Argon2Function.getInstance(memory, iterations, parallelism, length, Argon2.valueOf(type.toUpperCase()), version);
    }

    private HashingFunction getBCryptFunction() {
        int rounds = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS,
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT
        );
        String minor = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR,
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT
        );
        return BcryptFunction.getInstance(Bcrypt.valueOf(minor), rounds);
    }

}

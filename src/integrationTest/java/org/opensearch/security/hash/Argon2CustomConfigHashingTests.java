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

import java.util.List;
import java.util.Map;

import org.awaitility.Awaitility;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.ARGON2;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class Argon2CustomConfigHashingTests extends HashingTests {

    public static LocalCluster cluster;

    private static String type;
    private static int memory, iterations, length, parallelism, version;

    @BeforeClass
    public static void startCluster() {

        type = randomFrom(List.of("D", "I", "ID"));
        memory = randomFrom(List.of(4096, 8192, 15360));
        iterations = randomFrom((List.of(1, 2, 3, 4)));
        length = randomFrom((List.of(4, 8, 16, 32, 64)));
        parallelism = randomFrom(List.of(1, 2));
        version = randomFrom(List.of(16, 19));

        TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
            .hash(generateArgon2Hash("secret", type, memory, iterations, length, parallelism, version));

        cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(ADMIN_USER)
            .anonymousAuth(false)
            .nodeSettings(
                Map.of(
                    SECURITY_RESTAPI_ROLES_ENABLED,
                    List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                    SECURITY_PASSWORD_HASHING_ALGORITHM,
                    ARGON2,
                    SECURITY_PASSWORD_HASHING_ARGON2_TYPE,
                    type,
                    SECURITY_PASSWORD_HASHING_ARGON2_MEMORY,
                    memory,
                    SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS,
                    iterations,
                    SECURITY_PASSWORD_HASHING_ARGON2_LENGTH,
                    length,
                    SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM,
                    parallelism,
                    SECURITY_PASSWORD_HASHING_ARGON2_VERSION,
                    version
                )
            )
            .build();
        cluster.before();

        try (TestRestClient client = cluster.getRestClient(ADMIN_USER.getName(), "secret")) {
            Awaitility.await()
                .alias("Load default configuration")
                .until(() -> client.securityHealth().getTextFromJsonBody("/status"), equalTo("UP"));
        }
    }

    @Test
    public void shouldAuthenticateWithCorrectPassword() {
        String hash = generateArgon2Hash(PASSWORD, type, memory, iterations, length, parallelism, version);

        createUserWithHashedPassword(cluster, "user_1", hash);
        testPasswordAuth(cluster, "user_1", PASSWORD, SC_OK);

        createUserWithPlainTextPassword(cluster, "user_2", PASSWORD);
        testPasswordAuth(cluster, "user_2", PASSWORD, SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generateArgon2Hash(PASSWORD, type, memory, iterations, length, parallelism, version);
        createUserWithHashedPassword(cluster, "user_3", hash);
        testPasswordAuth(cluster, "user_3", "wrong_password", SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_4", PASSWORD);
        testPasswordAuth(cluster, "user_4", "wrong_password", SC_UNAUTHORIZED);
    }
}

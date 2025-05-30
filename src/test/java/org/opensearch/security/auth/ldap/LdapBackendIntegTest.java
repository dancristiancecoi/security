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

package org.opensearch.security.auth.ldap;

import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.srv.EmbeddedLDAPServer;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class LdapBackendIntegTest extends SingleClusterTest {

    private static EmbeddedLDAPServer ldapServer = null;

    private static int ldapPort;
    private static int ldapsPort;

    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
        ldapPort = ldapServer.getLdapPort();
        ldapsPort = ldapServer.getLdapsPort();
    }

    @Override
    protected String getResourceFolder() {
        return "ldap";
    }

    @Test
    public void testIntegLdapAuthenticationSSL() throws Exception {
        String securityConfigAsYamlString = FileHelper.loadFile("ldap/config.yml");
        securityConfigAsYamlString = securityConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfigAsYamlString(securityConfigAsYamlString), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();
        assertThat(rh.executeGetRequest("", encodeBasicHeader("jacksonm", "secret")).getStatusCode(), is(HttpStatus.SC_OK));
    }

    @Test
    public void testIntegLdapAuthenticationSSLFail() throws Exception {
        String securityConfigAsYamlString = FileHelper.loadFile("ldap/config.yml");
        securityConfigAsYamlString = securityConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfigAsYamlString(securityConfigAsYamlString), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();
        assertThat(rh.executeGetRequest("", encodeBasicHeader("wrong", "wrong")).getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
    }

    @Test
    public void testAttributesWithImpersonation() throws Exception {
        String securityConfigAsYamlString = FileHelper.loadFile("ldap/config.yml");
        securityConfigAsYamlString = securityConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS + ".cn=Captain Spock,ou=people,o=TEST", "*")
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfigAsYamlString(securityConfigAsYamlString), settings);
        final RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        assertThat(
            HttpStatus.SC_OK,
            is(
                (res = rh.executeGetRequest(
                    "_opendistro/_security/authinfo",
                    new BasicHeader("opendistro_security_impersonate_as", "jacksonm"),
                    encodeBasicHeader("spock", "spocksecret")
                )).getStatusCode()
            )
        );
        Assert.assertTrue(res.getBody().contains("ldap.dn"));
        Assert.assertTrue(res.getBody().contains("attr.ldap.entryDN"));
        Assert.assertTrue(res.getBody().contains("attr.ldap.subschemaSubentry"));

    }

    @AfterClass
    public static void tearDownLdap() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }
}

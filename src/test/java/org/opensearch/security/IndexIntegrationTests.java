/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.indices.InvalidIndexNameException;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class IndexIntegrationTests extends SingleClusterTest {

    @Test
    public void testComposite() throws Exception {

        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setConfig("composite_config.yml").setSecurityRoles("roles_composite.yml"),
            Settings.EMPTY,
            true
        );
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("starfleet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(
                new IndexRequest("klingonempire").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(new IndexRequest("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
        }

        String msearchBody = "{\"index\":\"starfleet\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"klingonempire\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"public\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        HttpResponse resc = rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("worf", "worf"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"_index\":\"klingonempire\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("hits"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("no permissions for [indices:data/read/search]"));

    }

    @Test
    public void testBulkShards() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles_bs.yml"), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            // create indices and mapping upfront
            tc.index(new IndexRequest("test").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("lorem").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON))
                .actionGet();
        }

        String bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"3\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"4\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"5\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"lorem\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"lorem\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"lorem\", \"_id\" : \"3\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"lorem\", \"_id\" : \"4\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"lorem\", \"_id\" : \"5\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"lorem\", \"_id\" : \"5\" } }"
            + System.lineSeparator();

        // _bulk
        HttpResponse res = rh.executePostRequest("_bulk?refresh=true&pretty=true", bulkBody, encodeBasicHeader("worf", "worf"));

        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(res.getBody().contains("\"errors\" : true"));
        Assert.assertTrue(res.getBody().contains("\"status\" : 201"));
        Assert.assertTrue(res.getBody().contains("no permissions for"));

        // check shards
        rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("nagilum", "nagilum"));

    }

    @Test
    public void testCreateIndex() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        assertThat(
            "Unable to create index 'nag'",
            rh.executePutRequest("nag1", null, encodeBasicHeader("nagilum", "nagilum")).getStatusCode(),
            is(HttpStatus.SC_OK)
        );
        assertThat(
            "Unable to create index 'starfleet_library'",
            rh.executePutRequest("starfleet_library", null, encodeBasicHeader("nagilum", "nagilum")).getStatusCode(),
            is(HttpStatus.SC_OK)
        );

        clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), clusterInfo.numNodes);

        assertThat(
            "Unable to close index 'starfleet_library'",
            rh.executePostRequest("starfleet_library/_close", null, encodeBasicHeader("nagilum", "nagilum")).getStatusCode(),
            is(HttpStatus.SC_OK)
        );

        assertThat(
            "Unable to open index 'starfleet_library'",
            (res = rh.executePostRequest("starfleet_library/_open", null, encodeBasicHeader("nagilum", "nagilum"))).getStatusCode(),
            is(HttpStatus.SC_OK)
        );
        Assert.assertTrue("open index 'starfleet_library' not acknowledged", res.getBody().contains("acknowledged"));
        Assert.assertFalse("open index 'starfleet_library' not acknowledged", res.getBody().contains("false"));

        clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), clusterInfo.numNodes);

        assertThat(HttpStatus.SC_FORBIDDEN, is(rh.executePutRequest("public", null, encodeBasicHeader("spock", "spock")).getStatusCode()));

    }

    @Test
    public void testFilteredAlias() throws Exception {

        setup();

        try (Client tc = getClient()) {

            tc.index(new IndexRequest("theindex").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("otherindex").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        AliasActions.add().alias("alias1").filter(QueryBuilders.termQuery("_type", "type1")).index("theindex")
                    )
                )
                .actionGet();
            tc.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        AliasActions.add().alias("alias2").filter(QueryBuilders.termQuery("_type", "type2")).index("theindex")
                    )
                )
                .actionGet();
            tc.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        AliasActions.add().alias("alias3").filter(QueryBuilders.termQuery("_type", "type2")).index("otherindex")
                    )
                )
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();

        // opendistro_security_user1 -> worf
        // opendistro_security_user2 -> picard

        HttpResponse resc = rh.executeGetRequest("alias*/_search", encodeBasicHeader("worf", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("theindex/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("alias3/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));

        resc = rh.executeGetRequest("_cat/indices", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));

    }

    @Test
    public void testIndexTypeEvaluation() throws Exception {

        setup();

        try (Client tc = getClient()) {
            tc.index(
                new IndexRequest("foo1").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("foo2").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)
            ).actionGet();
            tc.index(new IndexRequest("foo").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":3}", XContentType.JSON))
                .actionGet();
            tc.index(
                new IndexRequest("fooba").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}", XContentType.JSON)
            ).actionGet();

            try {
                tc.index(
                    new IndexRequest("x#a").id("4a").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}", XContentType.JSON)
                ).actionGet();
                Assert.fail("Indexname can contain #");
            } catch (InvalidIndexNameException e) {
                // expected
            }
        }

        RestHelper rh = nonSslRestHelper();

        HttpResponse resc = rh.executeGetRequest("/foo1/_search?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));

        resc = rh.executeGetRequest("/foo2/_search?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));

        resc = rh.executeGetRequest("/foo/_search?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 3"));

        // resc = rh.executeGetRequest("/fooba/z/_search?pretty", encodeBasicHeader("baz", "worf"));
        // assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/foo1/_doc/1?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));

        resc = rh.executeGetRequest("/foo2/_doc/2?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));

        resc = rh.executeGetRequest("/foo/_doc/3?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 3"));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));

        // resc = rh.executeGetRequest("/fooba/z/4?pretty", encodeBasicHeader("baz", "worf"));
        // assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // resc = rh.executeGetRequest("/foo*/_search?pretty", encodeBasicHeader("baz", "worf"));
        // assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/foo*,-fooba/_search?pretty", encodeBasicHeader("baz", "worf"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
    }

    @Test
    public void testIndices() throws Exception {

        setup();

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("nopermindex").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.index(new IndexRequest("logstash-1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd", SecurityUtils.EN_Locale);
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

            String date = sdf.format(new Date());
            tc.index(
                new IndexRequest("logstash-" + date).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
        }

        RestHelper rh = nonSslRestHelper();

        HttpResponse res = null;
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("/logstash-1/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        // nonexistent index with permissions
        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(
                rh.executeGetRequest("/logstash-nonex/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        // existent index without permissions
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/nopermindex/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        // nonexistent index without permissions
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executeGetRequest("/does-not-exist-and-no-perm/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        // nonexistent and existent index with permissions
        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(
                rh.executeGetRequest("/logstash-nonex,logstash-1/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        // existent index with permissions
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("/logstash-1/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        // nonexistent index with failed login
        assertThat(
            HttpStatus.SC_UNAUTHORIZED,
            is(rh.executeGetRequest("/logstash-nonex/_search", encodeBasicHeader("nouser", "nosuer")).getStatusCode())
        );

        // nonexistent index with no login
        assertThat((res = rh.executeGetRequest("/logstash-nonex/_search")).getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/_all/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/*/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executeGetRequest(
                    "/nopermindex,logstash-1,nonexist/_search",
                    encodeBasicHeader("opendistro_security_logstash", "nagilum")
                ).getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executeGetRequest("/logstash-1,nonexist/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/nonexist/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_OK,
            is(
                rh.executeGetRequest("/%3Clogstash-%7Bnow%2Fd%7D%3E/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executeGetRequest("/%3Cnonex-%7Bnow%2Fd%7D%3E/_search", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_OK,
            is(
                rh.executeGetRequest(
                    "/%3Clogstash-%7Bnow%2Fd%7D%3E,logstash-*/_search",
                    encodeBasicHeader("opendistro_security_logstash", "nagilum")
                ).getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_OK,
            is(
                rh.executeGetRequest(
                    "/%3Clogstash-%7Bnow%2Fd%7D%3E,logstash-1/_search",
                    encodeBasicHeader("opendistro_security_logstash", "nagilum")
                ).getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_CREATED,
            is(
                rh.executePutRequest("/logstash-b/_doc/1", "{}", encodeBasicHeader("opendistro_security_logstash", "nagilum"))
                    .getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_OK,
            is(
                rh.executePutRequest(
                    "/%3Clogstash-cnew-%7Bnow%2Fd%7D%3E",
                    "{}",
                    encodeBasicHeader("opendistro_security_logstash", "nagilum")
                ).getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_CREATED,
            is(
                rh.executePutRequest(
                    "/%3Clogstash-new-%7Bnow%2Fd%7D%3E/_doc/1",
                    "{}",
                    encodeBasicHeader("opendistro_security_logstash", "nagilum")
                ).getStatusCode()
            )
        );

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/_cat/indices?v", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode())
        );
        String body = res.getBody();
        Assert.assertTrue(body.contains("logstash-b"));
        Assert.assertTrue(body.contains("logstash-new-20"));
        Assert.assertTrue(body.contains("logstash-cnew-20"));
        Assert.assertFalse(body.contains("<"));
    }

    @Test
    public void testAliases() throws Exception {

        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH").build();

        setup(settings);

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("nopermindex").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.index(new IndexRequest("logstash-1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("logstash-5").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(
                new IndexRequest("logstash-del").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("logstash-del-ok").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();

            String date = new SimpleDateFormat("YYYY.MM.dd").format(new Date());
            tc.index(
                new IndexRequest("logstash-" + date).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();

            tc.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("nopermindex").alias("nopermalias")))
                .actionGet();
            tc.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices(".opendistro_security").alias("mysgi")))
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();

        HttpResponse res = null;

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executePostRequest("/mysgi/_doc", "{}", encodeBasicHeader("nagilum", "nagilum")).getStatusCode())
        );
        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/mysgi/_search?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode())
        );
        assertContains(res, "*\"hits\" : {*\"value\" : 0,*\"hits\" : [ ]*");

        // add alias to allowed index
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executePutRequest("/logstash-1/_alias/alog1", "", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        // add alias to not existing (no perm)
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executePutRequest("/nonexitent/_alias/alnp", "", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        // add alias to not existing (with perm)
        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(rh.executePutRequest("/logstash-nonex/_alias/alnp", "", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        // add alias to not allowed index
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executePutRequest("/nopermindex/_alias/alnp", "", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        String aliasRemoveIndex = "{"
            + "\"actions\" : ["
            + "{ \"add\":  { \"index\": \"logstash-del-ok\", \"alias\": \"logstash-del\" } },"
            + "{ \"remove_index\": { \"index\": \"logstash-del\" } }  "
            + "]"
            + "}";

        // remove_index
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executePostRequest("/_aliases", aliasRemoveIndex, encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        // get alias for permitted index
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("/logstash-1/_alias/alog1", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        // get alias for all indices
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/_alias/alog1", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        // get alias no perm
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("/_alias/nopermalias", encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );

        String alias = "{" + "\"aliases\": {" + "\"alias1\": {}" + "}" + "}";

        // create alias along with index
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executePutRequest("/beats-withalias", alias, encodeBasicHeader("aliasmngt", "nagilum")).getStatusCode())
        );
    }

    @Test
    public void testIndexResolveInvalidIndexName() throws Exception {
        setup();
        final RestHelper rh = nonSslRestHelper();

        // invalid_index_name_exception should be thrown and responded when invalid index name is mentioned in requests.
        HttpResponse res = rh.executeGetRequest(
            URLEncoder.encode("_##pdt_data/_search", "UTF-8"),
            encodeBasicHeader("ccsresolv", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        Assert.assertTrue(res.getBody().contains("invalid_index_name_exception"));
    }

    @Test
    public void testCCSIndexResolve() throws Exception {

        setup();
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.index(new IndexRequest(".abc-6").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
        }

        // ccsresolv has perm for ?abc*
        HttpResponse res = rh.executeGetRequest("ggg:.abc-6,.abc-6/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        res = rh.executeGetRequest("/*:.abc-6,.abc-6/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        // TODO: Change for 25.0 to be forbidden (possible bug in ES regarding ccs wildcard)
    }

    @Test
    @Ignore
    public void testCCSIndexResolve2() throws Exception {

        setup();
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.index(new IndexRequest(".abc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("xyz").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("noperm").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":3}", XContentType.JSON))
                .actionGet();

        }

        HttpResponse res = rh.executeGetRequest("/*:.abc,.abc/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":1"));

        res = rh.executeGetRequest("/ba*bcuzh/_search", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":12"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        res = rh.executeGetRequest("/*:.abc/_search", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":1"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        res = rh.executeGetRequest("/*:xyz,xyz/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":2"));

        // res = rh.executeGetRequest("/*noexist/_search", encodeBasicHeader("nagilum", "nagilum"));
        // assertThat(res.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        res = rh.executeGetRequest("/*:.abc/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":1"));

        res = rh.executeGetRequest("/*:xyz/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":2"));

        res = rh.executeGetRequest("/.abc/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/xyz/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:.abc,.abc/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:xyz,xyz/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:.abc/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:xyz/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:noperm/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:noperm/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("/*:noexists/_search", encodeBasicHeader("ccsresolv", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
    }

    @Test
    public void testIndexResolveIgnoreUnavailable() throws Exception {

        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setConfig("config_respect_indices_options.yml").setSecurityRoles("roles_bs.yml"),
            Settings.EMPTY,
            true
        );
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            // create indices and mapping upfront
            tc.index(new IndexRequest("test").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("lorem").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON))
                .actionGet();
        }

        String msearchBody = "{\"index\": [\"tes*\",\"-security\",\"-missing\"], \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"match_all\":{}}}"
            + System.lineSeparator();

        HttpResponse resc = rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("worf", "worf"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"total\":{\"value\":1"));
    }

    @Test
    public void testIndexResolveIndicesAlias() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            // create indices and mapping upfront
            tc.index(
                new IndexRequest("foo-index").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)
            ).actionGet();
            tc.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("foo-index").alias("foo-alias")))
                .actionGet();
            tc.admin().indices().delete(new DeleteIndexRequest("foo-index")).actionGet();
        }

        HttpResponse resc = rh.executeGetRequest("/_cat/aliases", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertFalse(resc.getBody().contains("foo"));

        resc = rh.executeGetRequest("/foo-alias/_search", encodeBasicHeader("foo_index", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/foo-index/_search", encodeBasicHeader("foo_index", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        resc = rh.executeGetRequest("/foo-alias/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

    }

    @Test
    public void testIndexResolveMinus() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            // create indices and mapping upfront
            tc.index(
                new IndexRequest("foo-abc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)
            ).actionGet();
        }

        HttpResponse resc = rh.executeGetRequest("/**/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/*/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/**,-foo*/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/*,-foo*/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/*,-*security/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));

        resc = rh.executeGetRequest("/*,-*security,-foo*/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));

        resc = rh.executeGetRequest("/_all,-*security/_search", encodeBasicHeader("foo_all", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resc = rh.executeGetRequest("/_all,-*security/_search", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

    }
}

/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.example.realm;

import org.apache.http.HttpEntity;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.client.transport.NoNodeAvailableException;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.xpack.client.PreBuiltXPackTransportClient;
import org.elasticsearch.xpack.core.XPackPlugin;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Integration test to test authentication with the custom realm. This test is run against an external cluster that is launched
 * by maven and this test is not expected to run within an IDE.
 */
public class CustomRealmIT extends ESIntegTestCase {

    // these users are configured external to this test in the integration test setup
    private static final String[] KNOWN_USERS = new String[] { "user1", "user2", "user3" };
    private static final String PASSWORD = "changeme";

    /**
     * The client used to connect to the external cluster must have authentication credentials since the cluster is
     * protected by shield
     */
    @Override
    protected Settings externalClusterClientSettings() {
        return Settings.builder()
                .put("transport.type", "security4")
                .put(ThreadContext.PREFIX + "." + CustomRealm.USER_HEADER, randomFrom(KNOWN_USERS))
                .put(ThreadContext.PREFIX + "." + CustomRealm.PW_HEADER, PASSWORD)
                .build();
    }

    /**
     * The plugins to load for the transport client. Shield must be loaded for the client in order to communicate with
     * a cluster protected by Shield.
     */
    @Override
    protected Collection<Class<? extends Plugin>> transportClientPlugins() {
        return Collections.singleton(XPackPlugin.class);
    }

    public void testHttpConnectionWithNoAuthentication() throws Exception {
        try {
            Response bad = getRestClient().performRequest("GET", "/", Collections.emptyMap());
            fail("an exception should be thrown but got: " + bad.getEntity().toString());
        } catch (ResponseException e) {
            Response response = e.getResponse();
            assertThat(response.getStatusLine().getStatusCode(), is(401));
            String value = response.getHeader("WWW-Authenticate");
            assertThat(value, is("custom-challenge"));
        }
    }

    public void testHttpAuthentication() throws Exception {
        Response response = getRestClient().performRequest("GET", "/", Collections.emptyMap(), (HttpEntity) null,
                new BasicHeader(CustomRealm.USER_HEADER, randomFrom(KNOWN_USERS)),
                new BasicHeader(CustomRealm.PW_HEADER, PASSWORD));
        assertThat(response.getStatusLine().getStatusCode(), is(200));
    }

    public void testTransportClient() throws Exception {
        NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().get();
        List<NodeInfo>  nodes = nodeInfos.getNodes();
        assertTrue(nodes.size() > 0);
        TransportAddress publishAddress = randomFrom(nodes).getTransport().address().publishAddress();
        String clusterName = nodeInfos.getClusterName().value();

        Settings settings = Settings.builder()
                .put("cluster.name", clusterName)
                .put(ThreadContext.PREFIX + "." + CustomRealm.USER_HEADER, randomFrom(KNOWN_USERS))
                .put(ThreadContext.PREFIX + "." + CustomRealm.PW_HEADER, PASSWORD)
                .build();
        try (TransportClient client = new PreBuiltXPackTransportClient(settings)) {
            client.addTransportAddress(publishAddress);
            ClusterHealthResponse response = client.admin().cluster().prepareHealth().execute().actionGet();
            assertThat(response.isTimedOut(), is(false));
        }
    }

    public void testTransportClientWrongAuthentication() throws Exception {
        NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().get();
        List<NodeInfo> nodes = nodeInfos.getNodes();
        assertTrue(nodes.size() > 0);
        TransportAddress publishAddress = randomFrom(nodes).getTransport().address().publishAddress();
        String clusterName = nodeInfos.getClusterName().value();

        Settings settings;
        if (randomBoolean()) {
            settings = Settings.builder()
                    .put("cluster.name", clusterName)
                    .put(ThreadContext.PREFIX + "." + CustomRealm.USER_HEADER, randomFrom(KNOWN_USERS) + randomAlphaOfLength(1))
                    .put(ThreadContext.PREFIX + "." + CustomRealm.PW_HEADER, PASSWORD)
                    .build();
        } else {
            settings = Settings.builder()
                    .put("cluster.name", clusterName)
                    .put(ThreadContext.PREFIX + "." + CustomRealm.USER_HEADER, randomFrom(KNOWN_USERS))
                    .put(ThreadContext.PREFIX + "." + CustomRealm.PW_HEADER, randomAlphaOfLengthBetween(16, 32))
                    .build();
        }

        try (TransportClient client = new PreBuiltXPackTransportClient(settings)) {
            client.addTransportAddress(publishAddress);
            client.admin().cluster().prepareHealth().execute().actionGet();
            fail("authentication failure should have resulted in a NoNodesAvailableException");
        } catch (NoNodeAvailableException e) {
            // expected
        }
    }

    public void testSettingsFiltering() throws Exception {
        Response response = getRestClient().performRequest("GET", "/_nodes/settings", Collections.emptyMap(), (HttpEntity) null,
            new BasicHeader(CustomRealm.USER_HEADER, randomFrom(KNOWN_USERS)),
            new BasicHeader(CustomRealm.PW_HEADER, PASSWORD));
        assertThat(response.getStatusLine().getStatusCode(), is(200));

        XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY, response.getEntity().getContent());
        XContentParser.Token token;
        Settings settings = null;
        while ((token = parser.nextToken()) != null) {
            if (token == XContentParser.Token.FIELD_NAME && parser.currentName().equals("settings")) {
                parser.nextToken();
                XContentBuilder builder = XContentBuilder.builder(parser.contentType().xContent());
                settings = Settings.builder()
                        .loadFromSource(builder.copyCurrentStructure(parser).bytes().utf8ToString(), XContentType.JSON)
                        .build();
                break;
            }
        }
        assertThat(settings, notNullValue());

        logger.error("settings for shield.authc.realms.custom.users {}", settings.getGroups("shield.authc.realms.custom.users"));
        // custom is the name configured externally...
        assertTrue(settings.getGroups("shield.authc.realms.custom.users").isEmpty());
    }
}

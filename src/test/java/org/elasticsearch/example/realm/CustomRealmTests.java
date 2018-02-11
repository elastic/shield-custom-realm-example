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

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.env.Environment;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.test.ESTestCase;

import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * Basic unit tests for the CustomRealm
 */
public class CustomRealmTests extends ESTestCase {

    public void testAuthenticate() {
        //setup
        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
                .put("type", CustomRealm.TYPE)
                .put("users.john.password", "doe")
                .put("users.john.roles", "user")
                .put("users.jane.password", "test")
                .putList("users.jane.roles", "user", "admin")
                .build();
        CustomRealm realm = new CustomRealm(new RealmConfig("test", realmSettings, globalSettings,
                new Environment(globalSettings, createTempDir()), new ThreadContext(globalSettings)));

        // authenticate john
        UsernamePasswordToken token = new UsernamePasswordToken("john", new SecureString(new char[] { 'd', 'o', 'e'}));
        realm.authenticate(token, ActionListener.wrap(result -> {
            assertTrue(result.isAuthenticated());
            User user = result.getUser();
            assertThat(user, notNullValue());
            assertThat(user.roles(), arrayContaining("user"));
            assertThat(user.principal(), equalTo("john"));
        }, e -> fail("Failed with exception: " + e.getMessage())));

        // authenticate jane
        token = new UsernamePasswordToken("jane", new SecureString(new char[] { 't', 'e', 's', 't'}));
        realm.authenticate(token, ActionListener.wrap(result -> {
            assertTrue(result.isAuthenticated());
            User user = result.getUser();
            assertThat(user, notNullValue());
            assertThat(user.roles(), arrayContaining("user", "admin"));
            assertThat(user.principal(), equalTo("jane"));
        }, e -> fail("Failed with exception: " + e.getMessage())));
    }

    public void testAuthenticateBadUser() {
        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
                .put("type", CustomRealm.TYPE)
                .put("users.john.password", "doe")
                .put("users.john.roles", "user")
                .put("users.jane.password", "test")
                .putList("users.jane.roles", "user", "admin")
                .build();

        CustomRealm realm = new CustomRealm(new RealmConfig("test", realmSettings, globalSettings,
                new Environment(globalSettings, createTempDir()), new ThreadContext(globalSettings)));
        UsernamePasswordToken token =
                new UsernamePasswordToken("john1", new SecureString(randomAlphaOfLengthBetween(4, 16).toCharArray()));
        realm.authenticate(token, ActionListener.wrap(result -> {
            assertFalse(result.isAuthenticated());
            assertThat(result.getUser(), nullValue());
        }, e -> fail("Failed with exception: " + e.getMessage())));
    }

}

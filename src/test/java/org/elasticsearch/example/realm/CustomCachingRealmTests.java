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
import org.elasticsearch.xpack.security.user.User;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.test.ESTestCase;

import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

/**
 * Unit tests for the CustomCachingRealm
 */
public class CustomCachingRealmTests extends ESTestCase {

    public void testAuthenticateWithCachedValue() {
        //setup
        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
                .put("type", CustomRealm.TYPE)
                .put("users.john.password", "doe")
                .put("users.john.roles", "user")
                .build();
        CustomCachingRealm realm = new CustomCachingRealm(new RealmConfig("test", realmSettings, globalSettings,
                new Environment(globalSettings), new ThreadContext(globalSettings)));

        // authenticate john
        UsernamePasswordToken token = new UsernamePasswordToken("john", new SecureString(new char[] { 'd', 'o', 'e'}));
        final User user = realm.authenticate(token);
        assertThat(user, notNullValue());
        assertThat(user.roles(), arrayContaining("user"));
        assertThat(user.principal(), equalTo("john"));

        // authenticate john again and we should be returned the same user object
        User user1 = realm.authenticate(token);
        assertThat(user1, sameInstance(user));

        // modify the cache entry with a changed password
        CustomCachingRealm.UserHolder holder = new CustomCachingRealm.UserHolder("changed".toCharArray(), user);
        realm.putInCache("john", holder);

        // try to authenticate again with the old password
        user1 = realm.authenticate(token);
        assertThat(user1, nullValue());

        // authenticate with new password
        token = new UsernamePasswordToken("john", new SecureString("changed".toCharArray()));
        user1 = realm.authenticate(token);
        assertThat(user1, sameInstance(user));

        // clear the cache
        if (randomBoolean()) {
            realm.expire("john");
        } else {
            realm.expireAll();
        }

        // authenticate with new password shouldn't work
        user1 = realm.authenticate(token);
        assertThat(user1, nullValue());

        // authenticate with correct password should work
        token = new UsernamePasswordToken("john", new SecureString(new char[] { 'd', 'o', 'e'}));
        user1 = realm.authenticate(token);
        assertThat(user1, not(nullValue()));
        assertThat(user1, not(sameInstance(user)));
        assertThat(user1, equalTo(user));
    }
}

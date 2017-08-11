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

import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.user.User;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.xpack.security.authc.support.CachingRealm;
import org.elasticsearch.xpack.security.authc.support.UsernamePasswordToken;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A custom implementation of a {@link CachingRealm} that shows what is necessary to integrate with the X-Pack cache
 * eviction APIs. A realm may need to cache data for performance reasons and if the cached data is changed in an external
 * system, the cache may need to be expired. By implementing the {@link CachingRealm} interface, the X-Pack cache eviction
 * API can be used to clear a user or the entire cache.
 *
 * This class merely extends the existing {@link CustomRealm} and implements a cache on top of the realm with a regular
 * {@link ConcurrentMap}. An actual cache implementation will be required for features such as LRU and time based evictions
 * with a size limit.
 */
public class CustomCachingRealm extends CustomRealm implements CachingRealm {

    public static final String TYPE = "caching-custom";

    private final ConcurrentMap<String, UserHolder> cache = new ConcurrentHashMap<>();

    public CustomCachingRealm(RealmConfig config) {
        super(TYPE, config);
    }

    /**
     * Overridden authenticate method that first checks the cache. If the user is not in the cache, the super method
     * is called and if a non-null value is returned, it is cached
     * @param authenticationToken the token to authenticate
     * @return {@link User} if authentication is successful, otherwise <code>null</code>
     */
    @Override
    public User authenticate(AuthenticationToken authenticationToken) {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        UserHolder userHolder = cache.get(token.principal());
        // NOTE the null check for the password. This is done because a cache is shared between authentication and lookup
        // lookup will not store the password...
        if (userHolder == null || userHolder.password == null) {
            User user = super.authenticate(token);
            if (user != null) {
                userHolder = new UserHolder(token.credentials().getChars(), user);
                cache.put(token.principal(), userHolder);
                return user;
            }
        } else if (token.credentials().equals(new SecureString(userHolder.password))) {
            return userHolder.user;
        }
        return null;
    }

    /**
     * Overridden method that will lookup a user from the cache first. If the user is not in the cache, then the super
     * method is called. A non-null result will be cached.
     * @param username the identifier for the user
     * @return {@link User} if found, otherwise <code>null</code>
     */
    @Override
    public User lookupUser(String username) {
        // a separate cache could be used for lookups to simplify the checking needed in the authenticate method but this
        // requires the lookup cache to also be cleared by the clear cache API
        UserHolder userHolder = cache.get(username);
        if (userHolder != null) {
            return userHolder.user;
        }

        User user = super.lookupUser(username);
        if (user != null) {
            userHolder = new UserHolder(null, user);
            cache.put(username, userHolder);
        }
        return user;
    }

    /**
     * Removes the entry from the cache identified by the username
     * @param username the identifier for the user to remove
     */
    @Override
    public void expire(String username) {
        cache.remove(username);
    }

    /**
     * Clears all entries from the cache
     */
    @Override
    public void expireAll() {
        cache.clear();
    }

    // method for testing to validate caching behavior works
    void putInCache(String username, UserHolder holder) {
        cache.put(username, holder);
    }

    static class UserHolder {
        private final char[] password;
        private final User user;

        UserHolder(char[] password, User user) {
            this.password = password;
            this.user = user;
        }
    }
}

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

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.authc.support.CachingRealm;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.core.security.user.User;

/**
 * A custom implementation of a {@link CachingRealm} that shows what is necessary to integrate with the X-Pack cache
 * eviction APIs. A realm may need to cache data for performance reasons and if the cached data is changed in an external
 * system, the cache may need to be expired. By implementing the {@link CachingRealm} interface, the X-Pack cache eviction
 * API can be used to clear a user or the entire cache.
 *
 * This class merely extends the existing {@link CustomRealm} and implements a cache on top of the realm using a
 * {@link Cache}.
 */
public class CustomCachingRealm extends CustomRealm implements CachingRealm {

    public static final String TYPE = "caching-custom";

    private final Cache<String, UserHolder> cache = CacheBuilder.<String, UserHolder>builder()
            .setExpireAfterAccess(TimeValue.timeValueMinutes(30))
            .build();

    public CustomCachingRealm(RealmConfig config) {
        super(TYPE, config);
    }

    /**
     * Method that handles the actual authentication of the token. This method will only be called if the token is a
     * supported token. The method validates the credentials of the user and if they match, a {@link User} will be
     * returned as the argument to the {@code listener}'s {@link ActionListener#onResponse(Object)} method. Else
     * {@code null} is returned.
     * @param authenticationToken the token to authenticate
     * @param listener return authentication result by calling {@link ActionListener#onResponse(Object)}
     */
    @Override
    public void authenticate(AuthenticationToken authenticationToken, ActionListener<AuthenticationResult> listener) {
        try {
            UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
            UserHolder userHolder = cache.get(token.principal());
            // NOTE the null check for the password. This is done because a cache is shared between authentication and lookup
            // lookup will not store the password...
            if (userHolder == null || userHolder.password == null) {
                super.authenticate(token, ActionListener.wrap(authenticationResult -> {
                    if (authenticationResult.isAuthenticated()) {
                        cache.put(token.principal(),
                                new UserHolder(token.credentials().clone().getChars(), authenticationResult.getUser()));
                    }
                    listener.onResponse(authenticationResult);
                }, listener::onFailure));
            } else if (token.credentials().equals(new SecureString(userHolder.password))) {
                listener.onResponse(AuthenticationResult.success(userHolder.user));
            } else {
                listener.onResponse(AuthenticationResult.notHandled());
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /**
     * Overridden method that will lookup a user from the cache first. If the user is not in the cache, then the super
     * method is called. A non-null result will be cached.
     * @param username the identifier for the user
     * @param listener used to return the user if one was looked or <code>null</code>
     */
    @Override
    public void lookupUser(String username, ActionListener<User> listener) {
        // a separate cache could be used for lookups to simplify the checking needed in the authenticate method but this
        // requires the lookup cache to also be cleared by the clear cache API
        UserHolder userHolder = cache.get(username);
        if (userHolder != null) {
            listener.onResponse(userHolder.user);
        } else {
            super.lookupUser(username, ActionListener.wrap(lookedUpUser -> {
                if (lookedUpUser != null) {
                    UserHolder holder = new UserHolder(null, lookedUpUser);
                    cache.put(username, holder);
                }
                listener.onResponse(lookedUpUser);
            }, listener::onFailure));
        }
    }

    /**
     * Removes the entry from the cache identified by the username
     * @param username the identifier for the user to remove
     */
    @Override
    public void expire(String username) {
        cache.invalidate(username);
    }

    /**
     * Clears all entries from the cache
     */
    @Override
    public void expireAll() {
        cache.invalidateAll();
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

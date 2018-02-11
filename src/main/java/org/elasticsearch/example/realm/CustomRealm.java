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
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.Realm;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * A custom {@link Realm} implementation that reads in users, passwords, and roles from the settings defined in the
 * elasticsearch configuration file. Please note, this method of storing authentication data is <b>not secure</b> and
 * is done as an example to demonstrate the workings of a realm in a simple manner.
 *
 * This custom realm also uses a different authentication scheme. The realm will extract a {@link UsernamePasswordToken}
 * that can be used for authentication, but does so in a non standard manner by retrieving the values from a header
 * in the request.
 */
public class CustomRealm extends Realm{

    /*
     * The type of the realm. This is defined as a static final variable to prevent typos
     */
    public static final String TYPE = "custom";

    public static final String USER_HEADER = "User";
    public static final String PW_HEADER = "Password";

    private final Map<String, InfoHolder> usersMap;

    /**
     * Constructor for the Realm. This constructor delegates to the super class to initialize the common aspects such
     * as the logger.
     * @param config the configuration specific to this realm
     */
    CustomRealm(RealmConfig config) {
        super(TYPE, config);
        // load all user data into a map for easy access - NOT SECURE!
        this.usersMap = parseUsersMap(config.settings());
    }

    /**
     * This constructor should be used by extending classes so that they can specify their own specific type
     * @param type the type of the realm
     * @param config the configuration specific to this realm
     */
    CustomRealm(String type, RealmConfig config) {
        super(TYPE, config);
        // load all user data into a map for easy access - NOT SECURE!
        this.usersMap = parseUsersMap(config.settings());
    }

    /**
     * Indicates whether this realm supports the given token. This realm only support {@link UsernamePasswordToken} objects
     * for authentication
     * @param token the token to test for support
     * @return true if the token is supported. false otherwise
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    /**
     * This method will extract a token from the given {@link RestRequest} if possible. This implementation of token
     * extraction looks for two headers, the <code>User</code> header for the username and the <code>Password</code>
     * header for the plaintext password
     * @param threadContext the {@link ThreadContext} that contains headers and transient objects for a request
     * @return the {@link AuthenticationToken} if possible to extract or <code>null</code>
     */
    @Override
    public UsernamePasswordToken token(ThreadContext threadContext) {
        String user = threadContext.getHeader(USER_HEADER);
        if (user != null) {
            String password = threadContext.getHeader(PW_HEADER);
            if (password != null) {
                return new UsernamePasswordToken(user, new SecureString(password.toCharArray()));
            }
        }
        return null;
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
            UsernamePasswordToken token = (UsernamePasswordToken)authenticationToken;
            final String actualUser = token.principal();
            final InfoHolder info = usersMap.get(actualUser);

            if (info != null && token.credentials().equals(info.password)) {
                listener.onResponse(AuthenticationResult.success(new User(actualUser, info.roles)));
            }
            else {
                listener.onResponse(AuthenticationResult.notHandled());
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /**
     * This method looks for a user that is identified by the given String. No authentication is performed by this method.
     * If this realm does not support user lookup, then this method will not be called.
     * @param username the identifier for the user
     * @param listener used to return lookup result
     */
    @Override
    public void lookupUser(String username, ActionListener<User> listener) {
        InfoHolder info = usersMap.get(username);
        if (info != null) {
            listener.onResponse(new User(username, info.roles));
        } else {
            listener.onResponse(null);
        }
    }

    /**
     * Utility method to extract a user from the realm's settings
     * @param settings the settings of the realm. This is not the node's settings
     * @return a {@link Map} of the usernames to the information about the user
     */
    private static Map<String, InfoHolder> parseUsersMap(Settings settings) {
        Map<String, Settings> usersSerttings = settings.getGroups("users");
        Map<String, InfoHolder> usersMap = new HashMap<>(usersSerttings.size());
        for (Entry<String, Settings> entry : usersSerttings.entrySet()) {
            Settings userSettings = entry.getValue();
            String username = entry.getKey();
            String password = userSettings.get("password");
            if (Strings.isEmpty(password)) {
                throw new IllegalArgumentException("password must be specified for user [" + username + "]");
            }
            usersMap.put(username, new InfoHolder(password, userSettings.getAsList("roles").toArray(new String[] {})));
        }
        return Collections.unmodifiableMap(usersMap);
    }

    /**
     * Class that holds the information about a user
     */
    private static class InfoHolder {
        private final String password;
        private final String[] roles;

        InfoHolder(String password, String[] roles) {
            this.password = password;
            this.roles = roles;
        }
    }
}

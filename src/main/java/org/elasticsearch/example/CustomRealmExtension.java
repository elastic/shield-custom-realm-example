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

package org.elasticsearch.example;

import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.example.realm.CustomAuthenticationFailureHandler;
import org.elasticsearch.example.realm.CustomCachingRealm;
import org.elasticsearch.example.realm.CustomCachingRealmFactory;
import org.elasticsearch.example.realm.CustomRealm;
import org.elasticsearch.example.realm.CustomRealmFactory;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.extensions.XPackExtension;
import org.elasticsearch.xpack.security.authc.AuthenticationFailureHandler;
import org.elasticsearch.xpack.security.authc.Realm.Factory;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

/**
 * The extension class that serves as the integration point between Elasticsearch, X-Pack, and the custom realm that is
 * provided by this extension.
 */
public class CustomRealmExtension extends XPackExtension {

    @Override
    public String name() {
        return "custom realm example";
    }

    @Override
    public String description() {
        return "a simple custom realm that can be used as the building block for a user specific realm";
    }

    /**
     * Returns a collection of header names that will be used by this extension. This is necessary to ensure the headers are copied from
     * the incoming request and made available to your realm(s).
     */
    @Override
    public Collection<String> getRestHeaders() {
        return Arrays.asList(CustomRealm.USER_HEADER, CustomRealm.PW_HEADER);
    }

    /**
     * Returns a map of the custom realms provided by this extension. The first parameter is the string representation of the realm type;
     * this is the value that is specified when declaring a realm in the settings. Note, the realm type cannot be one of the types
     * defined by X-Pack. In order to avoid a conflict, you may wish to use some prefix to your realm types.
     *
     * The second parameter is an instance of the {@link Factory} implementation. This factory class will be used to create realms of
     * this type that are defined in the elasticsearch settings.
     */
    @Override
    public Map<String, Factory> getRealms(ResourceWatcherService resourceWatcherService) {
        return new MapBuilder<String, Factory>()
                .put(CustomRealm.TYPE, new CustomRealmFactory())
                .put(CustomCachingRealm.TYPE, new CustomCachingRealmFactory())
                .immutableMap();
    }

    /**
     * Returns the custom authentication failure handler. Note only one implementation and instance of a failure handler can
     * exist. There is a default implementation, {@link org.elasticsearch.xpack.security.authc.DefaultAuthenticationFailureHandler} that
     * can be extended where appropriate. If no changes are needed to the default implementation, then there is no need to override this
     * method.
     */
    @Override
    public AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }
}

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

import org.elasticsearch.example.realm.CustomAuthenticationFailureHandler;
import org.elasticsearch.example.realm.CustomRealm;
import org.elasticsearch.example.realm.CustomRealmFactory;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.shield.authc.AuthenticationModule;

/**
 * The plugin class that serves as the integration point between Elasticsearch, Shield, and the custom realm that is
 * provided by this plugin. The most important method in this class is the {@see CustomRealmExamplePlugin#onModule}
 * method, which registers the custom {@link org.elasticsearch.shield.authc.Realm} and
 * {@link org.elasticsearch.shield.authc.AuthenticationFailureHandler}.
 */
public class CustomRealmExamplePlugin extends Plugin {

    @Override
    public String name() {
        return "custom realm example";
    }

    @Override
    public String description() {
        return "a simple custom realm that can be used as the building block for a user specific realm";
    }

    /**
     * Registers the custom authentication classes with the Shield AuthenticationModule. This method is very important;
     * without a proper implementation, Shield will not be able to locate your custom realm.
     *
     * This method is called by the Elasticsearch plugin framework and allows for custom interaction with the modules. In
     * this method, one or more custom realms can be registered and a custom authentication failure handler can also be
     * registered.
     *
     * @param authenticationModule the Shield AuthenticationModule
     */
    public void onModule(AuthenticationModule authenticationModule) {
        /*
         * Registers the custom realm. The first parameter is the String representation of a realm type; this is the
         * value that is specified when declaring a realm in the settings. Note, the realm type cannot be one of the
         * types defined by Shield. In order to avoid a conflict, you may wish to use some prefix to your realm types.
         *
         * The second parameter is the Realm.Factory implementation. This factory class will be used to create any realm
         * of this type that is defined in the elasticsearch settings.
         */
        authenticationModule.addCustomRealm(CustomRealm.TYPE, CustomRealmFactory.class);

        /*
         * Register the custom authentication failure handler. Note only one implementation of a failure handler can
         * exist and there is a default implementation that can be extended where appropriate. If no changes are needed
         * to the default implementation, then a custom failure handler does not need to be provided.
         */
        authenticationModule.setAuthenticationFailureHandler(CustomAuthenticationFailureHandler.class);
    }
}

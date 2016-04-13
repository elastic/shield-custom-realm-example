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

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;

/**
 * The factory class for the {@link CustomRealm}. This factory class is responsible for properly constructing the realm
 * when called by the X-Pack framework.
 */
public class CustomRealmFactory extends Realm.Factory<CustomRealm> {

    @Inject
    public CustomRealmFactory(RestController restController) {
        super(CustomRealm.TYPE, false);
        // we need to register the headers we use otherwise they will not be placed in the ThreadContext
        restController.registerRelevantHeaders(CustomRealm.USER_HEADER, CustomRealm.PW_HEADER);
    }

    /**
     * Create a {@link CustomRealm} based on the given configuration
     * @param config the configuration to create the realm with
     * @return the realm
     */
    @Override
    public CustomRealm create(RealmConfig config) {
        return new CustomRealm(config);
    }

    /**
     * Method that can be called to create a realm without configuration. This is called for internal realms only and
     * can simply return <code>null</code>
     * @param name the name of the realm
     * @return <code>null</code>
     */
    @Override
    public CustomRealm createDefault(String name) {
        return null;
    }
}

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

import org.elasticsearch.xpack.core.security.authc.Realm;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;

/**
 * The factory class for the {@link CustomCachingRealm}. This factory class is responsible for properly constructing the
 * realm when called by the X-Pack framework.
 */
public class CustomCachingRealmFactory implements Realm.Factory {

    /**
     * Create a {@link CustomRealm} based on the given configuration
     * @param config the configuration to create the realm with
     * @return the realm
     */
    @Override
    public CustomCachingRealm create(RealmConfig config) {
        return new CustomCachingRealm(config);
    }
}

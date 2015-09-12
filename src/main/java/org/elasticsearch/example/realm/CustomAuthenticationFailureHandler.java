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

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.DefaultAuthenticationFailureHandler;
import org.elasticsearch.transport.TransportMessage;

/**
 * A custom implementation of a {@link org.elasticsearch.shield.authc.AuthenticationFailureHandler}. The methods in this
 * class must return an {@link ElasticsearchSecurityException} with the appropriate status and headers for a client to
 * be able to handle an authentication failure. These methods can be called when there is a missing token, failure
 * to authenticate an extracted token, or when an exception occurs processing a request.
 *
 * This class extends the {@link DefaultAuthenticationFailureHandler} provided by Shield and changes the
 * <code>WWW-Authenticate</code> header to return a custom challenge for demonstration purposes. The default return
 * value is a 401 status with a Basic authentication challenge.
 */
public class CustomAuthenticationFailureHandler extends DefaultAuthenticationFailureHandler {

    @Override
    public ElasticsearchSecurityException unsuccessfulAuthentication(RestRequest request, AuthenticationToken token) {
        ElasticsearchSecurityException e = super.unsuccessfulAuthentication(request, token);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException unsuccessfulAuthentication(TransportMessage message, AuthenticationToken token, String action) {
        ElasticsearchSecurityException e = super.unsuccessfulAuthentication(message, token, action);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException missingToken(RestRequest request) {
        ElasticsearchSecurityException e = super.missingToken(request);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException missingToken(TransportMessage message, String action) {
        ElasticsearchSecurityException e = super.missingToken(message, action);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(RestRequest request, Exception e) {
        ElasticsearchSecurityException se = super.exceptionProcessingRequest(request, e);
        // set a custom header
        se.addHeader("WWW-Authenticate", "custom-challenge");
        return se;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(TransportMessage message, Exception e) {
        ElasticsearchSecurityException se = super.exceptionProcessingRequest(message, e);
        // set a custom header
        se.addHeader("WWW-Authenticate", "custom-challenge");
        return se;
    }

    @Override
    public ElasticsearchSecurityException authenticationRequired(String action) {
        ElasticsearchSecurityException se = super.authenticationRequired(action);
        // set a custom header
        se.addHeader("WWW-Authenticate", "custom-challenge");
        return se;
    }
}

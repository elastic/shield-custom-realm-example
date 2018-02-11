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
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.DefaultAuthenticationFailureHandler;
import org.elasticsearch.transport.TransportMessage;

/**
 * A custom implementation of a {@link org.elasticsearch.xpack.core.security.authc.AuthenticationFailureHandler}. The methods in this
 * class must return an {@link ElasticsearchSecurityException} with the appropriate status and headers for a client to
 * be able to handle an authentication failure. These methods can be called when there is a missing token, failure
 * to authenticate an extracted token, or when an exception occurs processing a request.
 *
 * This class extends the {@link DefaultAuthenticationFailureHandler} provided by X-Pack and changes the
 * <code>WWW-Authenticate</code> header to return a custom challenge for demonstration purposes. The default return
 * value is a 401 status with a Basic authentication challenge.
 *
 * Other implementations may choose to simply implement the {@link org.elasticsearch.xpack.core.security.authc.AuthenticationFailureHandler}
 * interface and construct the {@link ElasticsearchSecurityException} instances in the methods with the appropriate
 * {@link org.elasticsearch.rest.RestStatus} and headers. One example is for a realm that will integrate with a single
 * sign on service as in most cases these realms will need to redirect with a {@link org.elasticsearch.rest.RestStatus#FOUND}
 * and <code>Location</code> header with the URL to the SSO login page.
 */
public class CustomAuthenticationFailureHandler extends DefaultAuthenticationFailureHandler {

    @Override
    public ElasticsearchSecurityException failedAuthentication(RestRequest request, AuthenticationToken token, ThreadContext context) {
        ElasticsearchSecurityException e = super.failedAuthentication(request, token, context);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException failedAuthentication(TransportMessage message, AuthenticationToken token, String action,
                                                               ThreadContext context) {
        ElasticsearchSecurityException e = super.failedAuthentication(message, token, action, context);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException missingToken(RestRequest request, ThreadContext context) {
        ElasticsearchSecurityException e = super.missingToken(request, context);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException missingToken(TransportMessage message, String action, ThreadContext context) {
        ElasticsearchSecurityException e = super.missingToken(message, action, context);
        // set a custom header
        e.addHeader("WWW-Authenticate", "custom-challenge");
        return e;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(RestRequest request, Exception e, ThreadContext context) {
        ElasticsearchSecurityException se = super.exceptionProcessingRequest(request, e, context);
        // set a custom header
        se.addHeader("WWW-Authenticate", "custom-challenge");
        return se;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(TransportMessage message, String action, Exception e,
                                                                     ThreadContext context) {
        ElasticsearchSecurityException se = super.exceptionProcessingRequest(message, action, e, context);
        // set a custom header
        se.addHeader("WWW-Authenticate", "custom-challenge");
        return se;
    }

    @Override
    public ElasticsearchSecurityException authenticationRequired(String action, ThreadContext context) {
        ElasticsearchSecurityException se = super.authenticationRequired(action, context);
        // set a custom header
        se.addHeader("WWW-Authenticate", "custom-challenge");
        return se;
    }
}

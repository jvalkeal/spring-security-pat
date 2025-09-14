/*
 * Copyright 2025-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.jvalkeal.secpat.server.pat;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.github.jvalkeal.secpat.pat.config.AbstractPatConfigurer;

public final class PatTokenIntrospectionEndpointConfigurer extends AbstractPatConfigurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> introspectionRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> introspectionRequestConvertersConsumer = (
			introspectionRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	PatTokenIntrospectionEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	@Override
	public void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = PatAuthorizationServerConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		PatAuthorizationServerSettings patAuthorizationServerSettings = PatAuthorizationServerConfigurerUtils.getPatAuthorizationServerSettings(httpSecurity);
		String tokenIntrospectionEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? PatAuthorizationServerConfigurerUtils
					.withMultipleIssuersPattern(patAuthorizationServerSettings.getTokenIntrospectionEndpoint())
				: patAuthorizationServerSettings.getTokenIntrospectionEndpoint();

		this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, tokenIntrospectionEndpointUri);
		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);
		authenticationProviders.forEach(
				(authenticationProvider) -> httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	public void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = PatAuthorizationServerConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		PatAuthorizationServerSettings patAuthorizationServerSettings = PatAuthorizationServerConfigurerUtils.getPatAuthorizationServerSettings(httpSecurity);
		String tokenIntrospectionEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? PatAuthorizationServerConfigurerUtils
					.withMultipleIssuersPattern(patAuthorizationServerSettings.getTokenIntrospectionEndpoint())
				: patAuthorizationServerSettings.getTokenIntrospectionEndpoint();
		PatTokenIntrospectionEndpointFilter introspectionEndpointFilter = new PatTokenIntrospectionEndpointFilter(
				authenticationManager, tokenIntrospectionEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();

		if (!this.introspectionRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.introspectionRequestConverters);
		}
		this.introspectionRequestConvertersConsumer.accept(authenticationConverters);
		introspectionEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(authenticationManager, this.requestMatcher);
		httpSecurity.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);
		httpSecurity.addFilterAfter(postProcess(introspectionEndpointFilter), AuthorizationFilter.class);

	}

	@Override
	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();
		authenticationConverters.add(new PatTokenIntrospectionAuthenticationConverter());
		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
		PatTokenIntrospectionAuthenticationProvider tokenIntrospectionAuthenticationProvider = new PatTokenIntrospectionAuthenticationProvider(
				PatAuthorizationServerConfigurerUtils.getAuthorizationService(httpSecurity));
		authenticationProviders.add(tokenIntrospectionAuthenticationProvider);
		return authenticationProviders;
	}

}

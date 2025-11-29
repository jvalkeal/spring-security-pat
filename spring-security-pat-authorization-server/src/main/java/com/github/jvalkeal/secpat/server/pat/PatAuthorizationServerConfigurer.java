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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import com.github.jvalkeal.secpat.pat.config.AbstractPatConfigurer;

public class PatAuthorizationServerConfigurer extends AbstractHttpConfigurer<PatAuthorizationServerConfigurer, HttpSecurity> {

	private final Map<Class<? extends AbstractPatConfigurer>, AbstractPatConfigurer> configurers = createConfigurers();

	private RequestMatcher endpointsMatcher;

	@Override
	public void init(HttpSecurity httpSecurity) {
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		this.configurers.values().forEach((configurer) -> {
			configurer.init(httpSecurity);
			requestMatchers.add(configurer.getRequestMatcher());
		});
		this.endpointsMatcher = new OrRequestMatcher(requestMatchers);
		httpSecurity.csrf((csrf) -> csrf.ignoringRequestMatchers(this.endpointsMatcher));
		super.init(httpSecurity);
	}

	@Override
	public void configure(HttpSecurity httpSecurity) {
		this.configurers.values().forEach((configurer) -> configurer.configure(httpSecurity));
		super.configure(httpSecurity);
	}

	/**
	 * Get a {@link RequestMatcher} for an endpoint.
	 *
	 * @return endpoint request matcher
	 */
	public RequestMatcher getEndpointsMatcher() {
		return (request) -> {
			return this.endpointsMatcher.matches(request);
		};
	}

	/**
	 * Set a settings for pat server.
	 *
	 * @param patAuthorizationServerSettings the pat server settings
	 * @return this configurer
	 */
	public PatAuthorizationServerConfigurer patAuthorizationServerSettings(
			PatAuthorizationServerSettings patAuthorizationServerSettings) {
		Assert.notNull(patAuthorizationServerSettings, "patAuthorizationServerSettings cannot be null");
		getBuilder().setSharedObject(PatAuthorizationServerSettings.class, patAuthorizationServerSettings);
		return this;
	}

	/**
	 * Configure a introspection endpoint
	 *
	 * @param tokenIntrospectionEndpointCustomizer the instrospection endpoint customizer
	 * @return this configurer
	 */
	public PatAuthorizationServerConfigurer tokenIntrospectionEndpoint(
			Customizer<PatTokenIntrospectionEndpointConfigurer> tokenIntrospectionEndpointCustomizer) {
		tokenIntrospectionEndpointCustomizer.customize(getConfigurer(PatTokenIntrospectionEndpointConfigurer.class));
		return this;
	}

	@SuppressWarnings("unchecked")
	private <T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private Map<Class<? extends AbstractPatConfigurer>, AbstractPatConfigurer> createConfigurers() {
		Map<Class<? extends AbstractPatConfigurer>, AbstractPatConfigurer> configurers = new LinkedHashMap<>();
		configurers.put(PatTokenIntrospectionEndpointConfigurer.class,
				new PatTokenIntrospectionEndpointConfigurer(this::postProcess));
		return configurers;
	}

	/**
	 * Create a new instance of a {@link PatAuthorizationServerConfigurer}.
	 *
	 * @return instance of PatAuthorizationServerConfigurer
	 */
	public static PatAuthorizationServerConfigurer dsl() {
		return new PatAuthorizationServerConfigurer();
	}

}

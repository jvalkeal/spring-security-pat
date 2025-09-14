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

package com.github.jvalkeal.secpat.pat.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.github.jvalkeal.secpat.pat.PatAuthenticationConverter;
import com.github.jvalkeal.secpat.pat.PatAuthenticationProvider;
import com.github.jvalkeal.secpat.pat.PatTokenAuthenticationFilter;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;
import com.github.jvalkeal.secpat.pat.introspect.PatAuthorizationServicePatIntrospector;
import com.github.jvalkeal.secpat.pat.introspect.PatIntrospector;

public class PatConfigurer extends AbstractHttpConfigurer<PatConfigurer, HttpSecurity> {

	private final Map<Class<? extends AbstractPatConfigurer>, AbstractPatConfigurer> configurers = createConfigurers();
	PatIntrospector patIntrospector;
	AuthenticationManager authenticationManager;

	@Override
	public void init(HttpSecurity builder) throws Exception {
		super.init(builder);
	}

	public PatConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public PatConfigurer introspector(PatIntrospector introspector) {
		this.patIntrospector = introspector;
		return this;
	}

	public PatConfigurer authenticationConverter(PatAuthenticationConverter authenticationConverter) {
		return this;
	}

	public PatConfigurer endpointIntrospection(
			Customizer<PatIntrospectionEndpointConfigurer> tokenIntrospectionEndpointCustomizer) {
		tokenIntrospectionEndpointCustomizer.customize(getConfigurer(PatIntrospectionEndpointConfigurer.class));
		return this;
	}

	@SuppressWarnings({ "unused", "unchecked" })
	private <T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private Map<Class<? extends AbstractPatConfigurer>, AbstractPatConfigurer> createConfigurers() {
		Map<Class<? extends AbstractPatConfigurer>, AbstractPatConfigurer> configurers = new LinkedHashMap<>();
		configurers.put(PatIntrospectionEndpointConfigurer.class,
				new PatIntrospectionEndpointConfigurer(this::postProcess));
		return configurers;
	}

	PatIntrospector getIntrospector(HttpSecurity http) {
		if (this.patIntrospector != null) {
			return this.patIntrospector;
		}

		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		// if (context.getBeanNamesForType(PatTokenRepository.class).length > 0) {
		// 	PatTokenRepository patTokenRepository = context.getBean(PatTokenRepository.class);
		// 	return new PatTokenRepositoryPatIntrospector(patTokenRepository);
		// }

		// PatAuthorizationService patAuthorizationService2 = PatConfigurerUtils.getPatAuthorizationService(http);

		if (context.getBeanNamesForType(PatAuthorizationService.class).length > 0) {
			PatAuthorizationService patAuthorizationService = context.getBean(PatAuthorizationService.class);
			return new PatAuthorizationServicePatIntrospector(patAuthorizationService);
		}

		return context.getBean(PatIntrospector.class);
	}

	AuthenticationManager getAuthenticationManager(HttpSecurity http) {
		if (this.authenticationManager != null) {
			return this.authenticationManager;
		}
		return http.getSharedObject(AuthenticationManager.class);
	}

	AuthenticationProvider getAuthenticationProvider(HttpSecurity http) {
		PatIntrospector patIntrospector = getIntrospector(http);
		PatAuthenticationProvider provider = new PatAuthenticationProvider(patIntrospector);
		return provider;
	}


	@Override
	public void configure(HttpSecurity http) throws Exception {
		// AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		AuthenticationManager authenticationManager = getAuthenticationManager(http);
		PatTokenAuthenticationFilter filter = new PatTokenAuthenticationFilter(authenticationManager);
		http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

		AuthenticationProvider authenticationProvider = getAuthenticationProvider(http);
		http.authenticationProvider(authenticationProvider);
		// http.authenticationProvider(new PatAuthenticationProvider());

		// ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		// AuthenticationProvider authenticationProvider = getAuthenticationProvider();
		// if (authenticationProvider != null) {
		// 	http.authenticationProvider(authenticationProvider);
		// }


	}


		// AuthenticationProvider getAuthenticationProvider() {
		// 	if (this.authenticationManager != null) {
		// 		return null;
		// 	}
		// 	OpaqueTokenIntrospector introspector = getIntrospector();
		// 	OpaqueTokenAuthenticationProvider opaqueTokenAuthenticationProvider = new OpaqueTokenAuthenticationProvider(
		// 			introspector);
		// 	OpaqueTokenAuthenticationConverter authenticationConverter = getAuthenticationConverter();
		// 	if (authenticationConverter != null) {
		// 		opaqueTokenAuthenticationProvider.setAuthenticationConverter(authenticationConverter);
		// 	}
		// 	return opaqueTokenAuthenticationProvider;
		// }


		// OpaqueTokenIntrospector getIntrospector() {
		// 	if (this.introspector != null) {
		// 		return this.introspector.get();
		// 	}
		// 	return this.context.getBean(OpaqueTokenIntrospector.class);
		// }

	public static PatConfigurer dsl() {
		return new PatConfigurer();
	}

}

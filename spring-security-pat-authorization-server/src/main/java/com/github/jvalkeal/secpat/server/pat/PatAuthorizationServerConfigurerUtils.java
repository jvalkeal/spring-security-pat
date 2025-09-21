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

import java.util.Map;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.github.jvalkeal.secpat.pat.authorization.InMemoryPatAuthorizationRepository;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationRepository;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;
import com.github.jvalkeal.secpat.pat.authorization.RepositoryPatAuthorizationService;

final class PatAuthorizationServerConfigurerUtils {

	private PatAuthorizationServerConfigurerUtils() {
	}

	static String withMultipleIssuersPattern(String endpointUri) {
		Assert.hasText(endpointUri, "endpointUri cannot be empty");
		return endpointUri.startsWith("/") ? "/**" + endpointUri : "/**/" + endpointUri;
	}

	static AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = httpSecurity
			.getSharedObject(AuthorizationServerSettings.class);
		if (authorizationServerSettings == null) {
			authorizationServerSettings = getBean(httpSecurity, AuthorizationServerSettings.class);
			httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
		}
		return authorizationServerSettings;
	}

	static PatAuthorizationServerSettings getPatAuthorizationServerSettings(HttpSecurity httpSecurity) {
		PatAuthorizationServerSettings patAuthorizationServerSettings = httpSecurity
			.getSharedObject(PatAuthorizationServerSettings.class);
		if (patAuthorizationServerSettings == null) {
			patAuthorizationServerSettings = getBean(httpSecurity, PatAuthorizationServerSettings.class);
			httpSecurity.setSharedObject(PatAuthorizationServerSettings.class, patAuthorizationServerSettings);
		}
		return patAuthorizationServerSettings;
	}

	static RegisteredClientRepository getRegisteredClientRepository(HttpSecurity httpSecurity) {
		RegisteredClientRepository registeredClientRepository = httpSecurity
			.getSharedObject(RegisteredClientRepository.class);
		if (registeredClientRepository == null) {
			registeredClientRepository = getBean(httpSecurity, RegisteredClientRepository.class);
			httpSecurity.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		}
		return registeredClientRepository;
	}

	static OAuth2AuthorizationService getOauthAuthorizationService(HttpSecurity httpSecurity) {
		OAuth2AuthorizationService authorizationService = httpSecurity
			.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	static PatAuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		PatAuthorizationService authorizationService = httpSecurity
			.getSharedObject(PatAuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getOptionalBean(httpSecurity, PatAuthorizationService.class);
			if (authorizationService == null) {
				PatAuthorizationRepository authorizationRepository = httpSecurity
					.getSharedObject(PatAuthorizationRepository.class);
				if (authorizationRepository == null) {
					authorizationRepository = getOptionalBean(httpSecurity, PatAuthorizationRepository.class);
					if (authorizationRepository == null) {
						authorizationRepository = new InMemoryPatAuthorizationRepository();
					}
				}
				authorizationService = new RepositoryPatAuthorizationService(authorizationRepository);
			}
			httpSecurity.setSharedObject(PatAuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils
			.beansOfTypeIncludingAncestors(httpSecurity.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
					"Expected single matching bean of type '" + type.getName() + "' but found " + beansMap.size() + ": "
							+ StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

	static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
		return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
	}

}

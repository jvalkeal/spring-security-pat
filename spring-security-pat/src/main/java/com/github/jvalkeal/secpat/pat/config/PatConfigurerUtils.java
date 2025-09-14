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

import java.util.Map;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.StringUtils;

import com.github.jvalkeal.secpat.pat.authorization.InMemoryPatAuthorizationService;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;

final class PatConfigurerUtils {

	private PatConfigurerUtils() {
	}



	static <B extends HttpSecurityBuilder<B>> PatAuthorizationService getPatAuthorizationService(
			B builder) {
		PatAuthorizationService patAuthorizationService = getPatAuthorizationServiceBean(builder);
		if (patAuthorizationService == null) {
			patAuthorizationService = new InMemoryPatAuthorizationService();
		}
		return patAuthorizationService;
	}

	private static <B extends HttpSecurityBuilder<B>> PatAuthorizationService getPatAuthorizationServiceBean(
			B builder) {
		Map<String, PatAuthorizationService> patAuthorizationServiceMap = BeanFactoryUtils
			.beansOfTypeIncludingAncestors(builder.getSharedObject(ApplicationContext.class),
					PatAuthorizationService.class);
		if (patAuthorizationServiceMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(PatAuthorizationService.class,
					patAuthorizationServiceMap.size(),
					"Expected single matching bean of type '" + PatAuthorizationService.class.getName()
							+ "' but found " + patAuthorizationServiceMap.size() + ": "
							+ StringUtils.collectionToCommaDelimitedString(patAuthorizationServiceMap.keySet()));
		}
		return (!patAuthorizationServiceMap.isEmpty() ? patAuthorizationServiceMap.values().iterator().next() : null);
	}

}

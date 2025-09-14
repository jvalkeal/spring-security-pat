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

package com.github.jvalkeal.secpat.pat;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.github.jvalkeal.secpat.pat.introspect.PatIntrospector;

public class PatAuthenticationProvider implements AuthenticationProvider {

	private PatAuthenticationConverter authenticationConverter = PatAuthenticationProvider::convert;

	private final PatIntrospector introspector;

	public PatAuthenticationProvider(PatIntrospector introspector) {
		this.introspector = introspector;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof PatTokenAuthenticationToken token)) {
			return null;
		}
		// we expect introspection to do validation
		PatAuthenticatedPrincipal introspect = introspector.introspect(token.getKey());
		return authenticationConverter.convert(token.getKey(), introspect);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PatTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	static Authentication convert(String introspectedToken, PatAuthenticatedPrincipal authenticatedPrincipal) {
		PatTokenAuthenticationToken token = PatTokenAuthenticationToken.authenticated(authenticatedPrincipal.getName(),
				introspectedToken, authenticatedPrincipal.getAuthorities());
		return token;
	}

}

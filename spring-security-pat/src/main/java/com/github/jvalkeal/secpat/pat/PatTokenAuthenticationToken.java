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

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class PatTokenAuthenticationToken extends AbstractAuthenticationToken {

	private String user;
	private String key;
	private Object credentials;

	PatTokenAuthenticationToken(String user, String key, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.user = user;
		this.key = key;
	}

	@Override
	public Object getCredentials() {
		return credentials;
	}

	@Override
	public Object getPrincipal() {
		return PatAuthenticatedPrincipal.of(user, getAuthorities());
	}

	public String getKey() {
		return key;
	}

	public static PatTokenAuthenticationToken unauthenticated(String key) {
		return new PatTokenAuthenticationToken(null, key, null);
	}

	public static PatTokenAuthenticationToken authenticated(String user, String key,
			Collection<? extends GrantedAuthority> authorities) {
		PatTokenAuthenticationToken token = new PatTokenAuthenticationToken(user, key, authorities);
		token.setAuthenticated(true);
		return token;
	}

}

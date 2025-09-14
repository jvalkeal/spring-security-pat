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

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

public interface PatAuthenticatedPrincipal extends AuthenticatedPrincipal {

	Collection<? extends GrantedAuthority> getAuthorities();

	static PatAuthenticatedPrincipal of(String name, Collection<? extends GrantedAuthority> authorities) {
		return new DefaultApiKeyAuthenticatedPrincipal(name, authorities);
	}

	static class DefaultApiKeyAuthenticatedPrincipal implements PatAuthenticatedPrincipal {

		private String name;
		private Collection<? extends GrantedAuthority> authorities;

		DefaultApiKeyAuthenticatedPrincipal(String name, Collection<? extends GrantedAuthority> authorities) {
			this.name = name;
			this.authorities = authorities;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return authorities;
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("Name: [");
			sb.append(this.getName());
			sb.append("], Granted Authorities: [");
			sb.append(getAuthorities());
			sb.append("]");
			return sb.toString();
		}


	}
}

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

package com.github.jvalkeal.secpat.autoconfigure;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Spring Security Pat properties.
 *
 * @author Janne Valkealahti
 */
@ConfigurationProperties("spring.security.pat")
public class PatProperties {

	private List<Pat> pats = new ArrayList<>();

	public List<Pat> getPats() {
		return pats;
	}

	public void setPats(List<Pat> pats) {
		this.pats = pats;
	}

	public static class Pat {

		/**
		 * User principal.
		 */
		private String principal;

		/**
		 * User token value.
		 */
		private String token;

		/**
		 * Token scopes.
		 */
		private Set<String> scopes = new HashSet<>();

		/**
		 * {@link Instant} when user token was issued.
		 */
		private Instant issuedAt;

		/**
		 * {@link Instant} when user token will expire.
		 */
		private Instant expiresAt;

		/**
		 * {@link Instant} when user token is not yet valid.
		 */
		private Instant notBefore;

		public String getPrincipal() {
			return principal;
		}

		public void setPrincipal(String principal) {
			this.principal = principal;
		}

		public String getToken() {
			return token;
		}

		public void setToken(String token) {
			this.token = token;
		}

		public Set<String> getScopes() {
			return scopes;
		}

		public void setScopes(Set<String> scopes) {
			this.scopes = scopes;
		}

		public Instant getIssuedAt() {
			return issuedAt;
		}

		public void setIssuedAt(Instant issuedAt) {
			this.issuedAt = issuedAt;
		}

		public Instant getExpiresAt() {
			return expiresAt;
		}

		public void setExpiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
		}

		public Instant getNotBefore() {
			return notBefore;
		}

		public void setNotBefore(Instant notBefore) {
			this.notBefore = notBefore;
		}

	}

}

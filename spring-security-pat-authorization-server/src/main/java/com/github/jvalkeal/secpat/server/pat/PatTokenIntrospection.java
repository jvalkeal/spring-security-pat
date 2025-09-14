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

import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import com.github.jvalkeal.secpat.pat.introspect.PatTokenIntrospectionClaimAccessor;
import com.github.jvalkeal.secpat.pat.introspect.PatTokenIntrospectionClaimNames;

/**
 * A representation of the claims returned in a PAT Introspection Response.
 *
 * @author Janne Valkealahti
 * @see PatTokenIntrospectionClaimAccessor
 */
public final class PatTokenIntrospection implements PatTokenIntrospectionClaimAccessor, Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Map<String, Object> claims;

	private PatTokenIntrospection(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the claims in the Token Introspection Response.
	 * @return a {@code Map} of the claims
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Constructs a new {@link Builder} initialized with the {@link #isActive() active}
	 * claim to {@code false}.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return builder(false);
	}

	/**
	 * Constructs a new {@link Builder} initialized with the provided {@link #isActive()
	 * active} claim.
	 * @param active {@code true} if the token is currently active, {@code false}
	 * otherwise
	 * @return the {@link Builder}
	 */
	public static Builder builder(boolean active) {
		return new Builder(active);
	}

	/**
	 * Constructs a new {@link Builder} initialized with the provided claims.
	 * @param claims the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return builder().claims((c) -> c.putAll(claims));
	}

	/**
	 * A builder for {@link OAuth2TokenIntrospection}.
	 */
	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder(boolean active) {
			active(active);
		}

		/**
		 * Sets the indicator of whether or not the presented token is currently active,
		 * REQUIRED.
		 * @param active {@code true} if the token is currently active, {@code false}
		 * otherwise
		 * @return the {@link Builder} for further configuration
		 */
		public Builder active(boolean active) {
			return claim(PatTokenIntrospectionClaimNames.ACTIVE, active);
		}

		/**
		 * Add the scope associated with this token, OPTIONAL.
		 * @param scope the scope associated with this token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scope(String scope) {
			addClaimToClaimList(PatTokenIntrospectionClaimNames.SCOPE, scope);
			return this;
		}

		/**
		 * A {@code Consumer} of the scope(s) associated with this token, allowing the
		 * ability to add, replace, or remove, OPTIONAL.
		 * @param scopesConsumer a {@code Consumer} of the scope(s) associated with this
		 * token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(PatTokenIntrospectionClaimNames.SCOPE, scopesConsumer);
			return this;
		}

		/**
		 * Sets the client identifier for the OAuth 2.0 client that requested this token,
		 * OPTIONAL.
		 * @param clientId the client identifier for the OAuth 2.0 client that requested
		 * this token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientId(String clientId) {
			return claim(PatTokenIntrospectionClaimNames.CLIENT_ID, clientId);
		}

		/**
		 * Sets the human-readable identifier for the resource owner who authorized this
		 * token, OPTIONAL.
		 * @param username the human-readable identifier for the resource owner who
		 * authorized this token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder username(String username) {
			return claim(PatTokenIntrospectionClaimNames.USERNAME, username);
		}

		/**
		 * Sets the token type (e.g. bearer), OPTIONAL.
		 * @param tokenType the token type
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenType(String tokenType) {
			return claim(PatTokenIntrospectionClaimNames.TOKEN_TYPE, tokenType);
		}

		/**
		 * Sets the time indicating when this token will expire, OPTIONAL.
		 * @param expiresAt the time indicating when this token will expire
		 * @return the {@link Builder} for further configuration
		 */
		public Builder expiresAt(Instant expiresAt) {
			return claim(PatTokenIntrospectionClaimNames.EXP, expiresAt);
		}

		/**
		 * Sets the time indicating when this token was originally issued, OPTIONAL.
		 * @param issuedAt the time indicating when this token was originally issued
		 * @return the {@link Builder} for further configuration
		 */
		public Builder issuedAt(Instant issuedAt) {
			return claim(PatTokenIntrospectionClaimNames.IAT, issuedAt);
		}

		/**
		 * Sets the time indicating when this token is not to be used before, OPTIONAL.
		 * @param notBefore the time indicating when this token is not to be used before
		 * @return the {@link Builder} for further configuration
		 */
		public Builder notBefore(Instant notBefore) {
			return claim(PatTokenIntrospectionClaimNames.NBF, notBefore);
		}

		/**
		 * Sets the subject of the token, usually a machine-readable identifier of the
		 * resource owner who authorized this token, OPTIONAL.
		 * @param subject the subject of the token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder subject(String subject) {
			return claim(PatTokenIntrospectionClaimNames.SUB, subject);
		}

		/**
		 * Add the identifier representing the intended audience for this token, OPTIONAL.
		 * @param audience the identifier representing the intended audience for this
		 * token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder audience(String audience) {
			addClaimToClaimList(PatTokenIntrospectionClaimNames.AUD, audience);
			return this;
		}

		/**
		 * A {@code Consumer} of the intended audience(s) for this token, allowing the
		 * ability to add, replace, or remove, OPTIONAL.
		 * @param audiencesConsumer a {@code Consumer} of the intended audience(s) for
		 * this token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder audiences(Consumer<List<String>> audiencesConsumer) {
			acceptClaimValues(PatTokenIntrospectionClaimNames.AUD, audiencesConsumer);
			return this;
		}

		/**
		 * Sets the issuer of this token, OPTIONAL.
		 * @param issuer the issuer of this token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder issuer(String issuer) {
			return claim(PatTokenIntrospectionClaimNames.ISS, issuer);
		}

		/**
		 * Sets the identifier for the token, OPTIONAL.
		 * @param jti the identifier for the token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder id(String jti) {
			return claim(PatTokenIntrospectionClaimNames.JTI, jti);
		}

		/**
		 * Sets the claim.
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link Builder} for further configuration
		 */
		public Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Validate the claims and build the {@link PatTokenIntrospection}.
		 * <p>
		 * The following claims are REQUIRED: {@code active}
		 * @return the {@link OAuth2TokenIntrospection}
		 */
		public PatTokenIntrospection build() {
			validate();
			return new PatTokenIntrospection(this.claims);
		}

		private void validate() {
			Assert.notNull(this.claims.get(PatTokenIntrospectionClaimNames.ACTIVE), "active cannot be null");
			Assert.isInstanceOf(Boolean.class, this.claims.get(PatTokenIntrospectionClaimNames.ACTIVE),
					"active must be of type boolean");
			if (this.claims.containsKey(PatTokenIntrospectionClaimNames.SCOPE)) {
				Assert.isInstanceOf(List.class, this.claims.get(PatTokenIntrospectionClaimNames.SCOPE),
						"scope must be of type List");
			}
			if (this.claims.containsKey(PatTokenIntrospectionClaimNames.EXP)) {
				Assert.isInstanceOf(Instant.class, this.claims.get(PatTokenIntrospectionClaimNames.EXP),
						"exp must be of type Instant");
			}
			if (this.claims.containsKey(PatTokenIntrospectionClaimNames.IAT)) {
				Assert.isInstanceOf(Instant.class, this.claims.get(PatTokenIntrospectionClaimNames.IAT),
						"iat must be of type Instant");
			}
			if (this.claims.containsKey(PatTokenIntrospectionClaimNames.NBF)) {
				Assert.isInstanceOf(Instant.class, this.claims.get(PatTokenIntrospectionClaimNames.NBF),
						"nbf must be of type Instant");
			}
			if (this.claims.containsKey(PatTokenIntrospectionClaimNames.AUD)) {
				Assert.isInstanceOf(List.class, this.claims.get(PatTokenIntrospectionClaimNames.AUD),
						"aud must be of type List");
			}
			if (this.claims.containsKey(PatTokenIntrospectionClaimNames.ISS)) {
				validateURL(this.claims.get(PatTokenIntrospectionClaimNames.ISS), "iss must be a valid URL");
			}
		}

		@SuppressWarnings("unchecked")
		private void addClaimToClaimList(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.computeIfAbsent(name, (k) -> new LinkedList<String>());
			((List<String>) this.claims.get(name)).add(value);
		}

		@SuppressWarnings("unchecked")
		private void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(valuesConsumer, "valuesConsumer cannot be null");
			this.claims.computeIfAbsent(name, (k) -> new LinkedList<String>());
			List<String> values = (List<String>) this.claims.get(name);
			valuesConsumer.accept(values);
		}

		private static void validateURL(Object url, String errorMessage) {
			if (URL.class.isAssignableFrom(url.getClass())) {
				return;
			}

			try {
				new URI(url.toString()).toURL();
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}

	}

}

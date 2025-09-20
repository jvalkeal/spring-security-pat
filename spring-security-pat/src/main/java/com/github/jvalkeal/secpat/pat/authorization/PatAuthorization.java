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

package com.github.jvalkeal.secpat.pat.authorization;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.springframework.util.Assert;

/**
 * Represents a PAT (Personal Access Token) authorization with principal, scopes, and token metadata.
 */
public interface PatAuthorization {

	/**
	 * Returns the identifier associated with this authorization.
	 * @return the identifier
	 */
	String getId();

	/**
	 * Returns the name associated with this authorization.
	 * @return the name
	 */
	String getName();

	/**
	 * Returns the description associated with this authorization.
	 * @return the description
	 */
	String getDescription();

	/**
	 * Returns the principal associated with this authorization.
	 * @return the principal name
	 */
	String getPrincipal();

	/**
	 * Returns the scopes granted to this authorization.
	 * @return a set of scope strings
	 */
	Set<String> getScopes();

	/**
	 * Returns the token value for this authorization.
	 * @return the token string
	 */
	String getToken();

	/**
	 * Returns the instant when the token was issued.
	 * @return the issued at instant
	 */
	Instant getIssuedAt();

	/**
	 * Returns the instant when the token expires.
	 * @return the expiration instant
	 */
	Instant getExpiresAt();

	/**
	 * Returns the instant before which the token is not valid.
	 * @return the not before instant
	 */
	Instant getNotBefore();

	/**
	 * Builder for creating {@link PatAuthorization} instances.
	 */
	interface Builder {

		/**
		 * Sets the id for the authorization.
		 * @param id the id
		 * @return this builder
		 */
		Builder id(String id);

		/**
		 * Sets the name for the authorization.
		 * @param name the name
		 * @return this builder
		 */
		Builder name(String name);

		/**
		 * Sets the description for the authorization.
		 * @param description the description
		 * @return this builder
		 */
		Builder description(String description);

		/**
		 * Sets the principal for the authorization.
		 * @param principal the principal name
		 * @return this builder
		 */
		Builder principal(String principal);

		/**
		 * Sets the scopes for the authorization.
		 * @param scopes the set of scopes
		 * @return this builder
		 */
		Builder scopes(Set<String> scopes);

		/**
		 * Adds a scope for the authorization.
		 * @param scope the scope
		 * @return this builder
		 */
		Builder scope(String... scope);

		/**
		 * Sets the token value.
		 * @param token the token string
		 * @return this builder
		 */
		Builder token(String token);

		/**
		 * Sets the issued at instant.
		 * @param issuedAt the issued at instant
		 * @return this builder
		 */
		Builder issuedAt(Instant issuedAt);

		/**
		 * Sets the expiration instant.
		 * @param expiresAt the expiration instant
		 * @return this builder
		 */
		Builder expiresAt(Instant expiresAt);

		/**
		 * Sets the not before instant.
		 * @param notBefore the not before instant
		 * @return this builder
		 */
		Builder notBefore(Instant notBefore);

		/**
		 * Builds the {@link PatAuthorization} instance.
		 * @return the built instance
		 */
		PatAuthorization build();
	}

	/**
	 * Creates a new builder for {@link PatAuthorization}.
	 * @return a new builder instance
	 */
	static Builder builder() {
		return new DefaultPatAuthorization.Builder();
	}

	/**
	 * Default implementation of {@link PatAuthorization}.
	 */
	class DefaultPatAuthorization implements PatAuthorization {

		private final String id;
		private final String name;
		private final String description;
		private final String principal;
		private final Set<String> scopes;
		private final String token;
		private final Instant issuedAt;
		private final Instant expiresAt;
		private final Instant notBefore;

		/**
		 * Constructs a new instance using the provided builder.
		 * @param builder the builder with values
		 */
		private DefaultPatAuthorization(Builder builder) {
			this.id = builder.id;
			this.name = builder.name;
			this.description = builder.description;
			this.principal = builder.principal;
			this.scopes = builder.scopes;
			this.token = builder.token;
			this.issuedAt = builder.issuedAt;
			this.expiresAt = builder.expiresAt;
			this.notBefore = builder.notBefore;
		}

		@Override
		public String getId() {
			return id;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public String getPrincipal() {
			return principal;
		}

		@Override
		public Set<String> getScopes() {
			return scopes;
		}

		@Override
		public String getToken() {
			return token;
		}

		@Override
		public Instant getIssuedAt() {
			return issuedAt;
		}

		@Override
		public Instant getExpiresAt() {
			return expiresAt;
		}

		@Override
		public Instant getNotBefore() {
			return notBefore;
		}

		/**
		 * Builder for {@link DefaultPatAuthorization}.
		 */
		public static class Builder implements PatAuthorization.Builder {
			private String id;
			private String name;
			private String description;
			private String principal;
			private Set<String> scopes = new HashSet<>();
			private String token;
			private Instant issuedAt;
			private Instant expiresAt;
			private Instant notBefore;

			@Override
			public Builder id(String id) {
				this.id = id;
				return this;
			}

			@Override
			public Builder name(String name) {
				this.name = name;
				return this;
			}

			@Override
			public Builder description(String description) {
				this.description = description;
				return this;
			}

			public Builder principal(String principal) {
				this.principal = principal;
				return this;
			}

			public Builder scopes(Set<String> scopes) {
				this.scopes = scopes;
				return this;
			}

			@Override
			public Builder scope(String... scope) {
				for (String s : scope) {
					scopes.add(s);
				}
				return this;
			}

			public Builder token(String token) {
				this.token = token;
				return this;
			}

			public Builder issuedAt(Instant issuedAt) {
				this.issuedAt = issuedAt;
				return this;
			}

			public Builder expiresAt(Instant expiresAt) {
				this.expiresAt = expiresAt;
				return this;
			}

			public Builder notBefore(Instant notBefore) {
				this.notBefore = notBefore;
				return this;
			}

			public PatAuthorization build() {
				Assert.notNull(principal, "principal cannot be null");
				Assert.notNull(scopes, "scopes cannot be null");
				Assert.notNull(token, "token cannot be null");
				Assert.notNull(issuedAt, "issuedAt cannot be null");
				Assert.notNull(expiresAt, "expiresAt cannot be null");
				Assert.notNull(notBefore, "notBefore cannot be null");
				if (issuedAt.isAfter(expiresAt)) {
					throw new IllegalArgumentException("issuedAt can't be after expiresAt");
				}
				if (notBefore.isAfter(expiresAt)) {
					throw new IllegalArgumentException("notBefore can't be after expiresAt");
				}
				return new DefaultPatAuthorization(this);
			}
		}
	}
}

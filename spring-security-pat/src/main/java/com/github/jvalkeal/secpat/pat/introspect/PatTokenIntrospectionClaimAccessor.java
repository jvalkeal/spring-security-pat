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

package com.github.jvalkeal.secpat.pat.introspect;

import java.time.Instant;
import java.util.List;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;

public interface PatTokenIntrospectionClaimAccessor extends ClaimAccessor {

	@Nullable
	default List<String> getScopes() {
		return getClaimAsStringList(PatTokenIntrospectionClaimNames.SCOPE);
	}

	/**
	 * Returns a timestamp {@code (exp)} indicating when the token expires
	 * @return a timestamp indicating when the token expires
	 */
	@Nullable
	default Instant getExpiresAt() {
		return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.EXP);
	}

	/**
	 * Returns a timestamp {@code (iat)} indicating when the token was issued
	 * @return a timestamp indicating when the token was issued
	 */
	@Nullable
	default Instant getIssuedAt() {
		return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.IAT);
	}

	/**
	 * Returns a timestamp {@code (nbf)} indicating when the token is not to be used
	 * before
	 * @return a timestamp indicating when the token is not to be used before
	 */
	@Nullable
	default Instant getNotBefore() {
		return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.NBF);
	}

}

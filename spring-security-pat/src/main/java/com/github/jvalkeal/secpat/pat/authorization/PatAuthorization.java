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
import java.util.Set;

import org.springframework.util.Assert;

public class PatAuthorization {

	private String principalName;
	private Set<String> authorizedScopes;
	private String token;
	private Instant issuedAt;
	private Instant expiresAt;
	private Instant notBefore;

	public PatAuthorization(String principalName, Set<String> authorizedScopes, String token, Instant issuedAt,
			Instant expiresAt, Instant notBefore) {
		Assert.notNull(principalName, "principalName cannot be null");
		Assert.notNull(authorizedScopes, "authorizedScopes cannot be null");
		Assert.notNull(token, "token cannot be null");
		Assert.notNull(issuedAt, "issuedAt cannot be null");
		Assert.notNull(expiresAt, "expiresAt cannot be null");
		Assert.notNull(notBefore, "notBefore cannot be null");
		this.principalName = principalName;
		this.authorizedScopes = authorizedScopes;
		this.token = token;
		this.issuedAt = issuedAt;
		this.expiresAt = expiresAt;
		this.notBefore = notBefore;
		if (issuedAt.isAfter(expiresAt)) {
			throw new IllegalArgumentException("issuedAt can't be after expiresAt");
		}
		if (notBefore.isAfter(expiresAt)) {
			throw new IllegalArgumentException("notBefore can't be after expiresAt");
		}
	}

	public String getPrincipalName() {
		return principalName;
	}

	public Set<String> getAuthorizedScopes() {
		return authorizedScopes;
	}

	public String getToken() {
		return token;
	}

	public Instant getIssuedAt() {
		return issuedAt;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public Instant getNotBefore() {
		return notBefore;
	}
}

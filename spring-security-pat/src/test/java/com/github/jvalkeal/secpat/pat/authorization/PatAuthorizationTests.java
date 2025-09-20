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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class PatAuthorizationTests {

	@Test
	void allArgumentsMustBeSet() {
		String principalName = "fake";
		Set<String> authorizedScopes = Collections.emptySet();
		String token = "fake";
		Instant now = Instant.now();

		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(null).scopes(authorizedScopes).token(token).issuedAt(now)
					.expiresAt(now).notBefore(now).build();
		}).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(null).token(token).issuedAt(now).expiresAt(now)
					.notBefore(now).build();
		}).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(authorizedScopes).token(null).issuedAt(now)
					.expiresAt(now).notBefore(now).build();
		}).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(authorizedScopes).token(token).issuedAt(null)
					.expiresAt(now).notBefore(now).build();
		}).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(authorizedScopes).token(token).issuedAt(now)
					.expiresAt(null).notBefore(now).build();
		}).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(authorizedScopes).token(token).issuedAt(now)
					.expiresAt(now).notBefore(null).build();
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void wrongTimesThrows() {
		String principalName = "fake";
		Set<String> authorizedScopes = Collections.emptySet();
		String token = "fake";
		Instant before = Instant.now();
		Instant after = before.plusSeconds(1);

		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(authorizedScopes).token(token).issuedAt(after)
					.expiresAt(before).notBefore(before).build();
		}).isInstanceOf(IllegalArgumentException.class);

		assertThatThrownBy(() -> {
			PatAuthorization.builder().principal(principalName).scopes(authorizedScopes).token(token).issuedAt(before)
					.expiresAt(before).notBefore(after).build();
		}).isInstanceOf(IllegalArgumentException.class);
	}
}

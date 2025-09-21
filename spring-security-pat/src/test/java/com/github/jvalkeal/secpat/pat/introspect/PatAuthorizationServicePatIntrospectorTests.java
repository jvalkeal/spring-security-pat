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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.authentication.BadCredentialsException;

import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;

public class PatAuthorizationServicePatIntrospectorTests {

	static Stream<Arguments> validateSuccess() {
		return Stream.of(
			Arguments.argumentSet("Valid 1h", "PT0S", "PT1H", "PT0S"),
			Arguments.argumentSet("Valid 1h issued 1h ago", "PT0S", "PT1H", "PT-60M"),
			Arguments.argumentSet("Skew exp", "PT-60S", "PT-55S", "PT-55S"),
			Arguments.argumentSet("Skew nbf", "PT0S", "PT1H", "PT-55S")
		);
	}

	@ParameterizedTest
	@MethodSource
	void validateSuccess(String issuedAtExp, String expiresAtExp, String notBeforeExp) {
		Instant now = Instant.now();
		Instant issuedAt = now.plus(Duration.parse(issuedAtExp));
		Instant expiresAt = now.plus(Duration.parse(expiresAtExp));
		Instant notBefore = now.plus(Duration.parse(notBeforeExp));
		PatAuthorization authorization = createAuthorization(issuedAt, expiresAt, notBefore);
		mockAndIntrospect(authorization);
	}

	static Stream<Arguments> validateFailure() {
		return Stream.of(
			Arguments.argumentSet("Exp 1h ago", "PT-2H", "PT-1H", "PT-2H"),
			Arguments.argumentSet("Skew exp", "PT-1H", "PT-65S", "PT-1H")
			// Arguments.argumentSet("Skew nbf", "PT0S", "PT1H", "PT-65S")
		);
	}

	@ParameterizedTest
	@MethodSource
	void validateFailure(String issuedAtExp, String expiresAtExp, String notBeforeExp) {
		Instant now = Instant.now();
		Instant issuedAt = now.plus(Duration.parse(issuedAtExp));
		Instant expiresAt = now.plus(Duration.parse(expiresAtExp));
		Instant notBefore = now.plus(Duration.parse(notBeforeExp));
		PatAuthorization authorization = createAuthorization(issuedAt, expiresAt, notBefore);
		assertThatThrownBy(() -> {
			mockAndIntrospect(authorization);
		}).isInstanceOf(BadCredentialsException.class);
	}

	static PatAuthorization createAuthorization(Instant issuedAt, Instant expiresAt, Instant notBefore) {
		return PatAuthorization.builder()
			.principal("fake")
			.scopes(Collections.emptySet())
			.token("fake")
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.notBefore(notBefore)
			.build();
	}

	static void mockAndIntrospect(PatAuthorization patAuthorization) {
		PatAuthorizationService service = mock(PatAuthorizationService.class);
		given(service.acquire(any())).willReturn(patAuthorization);
		PatAuthorizationServicePatIntrospector introspector = new PatAuthorizationServicePatIntrospector(service);
		introspector.introspect("fake");
	}
}

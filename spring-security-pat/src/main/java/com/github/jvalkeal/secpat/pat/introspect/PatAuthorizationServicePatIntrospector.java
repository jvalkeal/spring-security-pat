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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import com.github.jvalkeal.secpat.pat.PatAuthenticatedPrincipal;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;
import com.github.jvalkeal.secpat.pat.authorization.RepositoryPatAuthorizationService;

/**
 * {@link PatIntrospector} implementation using {@link PatAuthorizationService}.
 *
 * @author Janne Valkealahti
 * @see RepositoryPatAuthorizationService
 */
public class PatAuthorizationServicePatIntrospector implements PatIntrospector {

	private final PatAuthorizationService authorizationService;

	public PatAuthorizationServicePatIntrospector(PatAuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public PatAuthenticatedPrincipal introspect(String token) {
		PatAuthorization patAuthorization = authorizationService
				.acquire(PatAuthorizationService.AcquireContext.ofToken(token));
		if (patAuthorization == null) {
			throw new BadCredentialsException("no token match");
		}
		else {
			validate(patAuthorization);
		}
		Collection<? extends GrantedAuthority> authorities = patAuthorization.getScopes().stream()
			.map(role -> new SimpleGrantedAuthority(role))
			.collect(Collectors.toList());
		return PatAuthenticatedPrincipal.of(patAuthorization.getPrincipal(), authorities);
	}

	private void validate(PatAuthorization patAuthorization) {
		Clock clock = Clock.systemUTC();
		Duration clockSkew = Duration.of(60, ChronoUnit.SECONDS);
		Instant expiry = patAuthorization.getExpiresAt();
		if (expiry != null) {
			if (Instant.now(clock).minus(clockSkew).isAfter(expiry)) {
				throw new BadCredentialsException("token time not valid");
			}
		}
		Instant before = patAuthorization.getNotBefore();
		if (before != null) {
			if (Instant.now(clock).plus(clockSkew).isBefore(before)) {
				throw new BadCredentialsException("token not yet valid");
			}
		}
	}

}

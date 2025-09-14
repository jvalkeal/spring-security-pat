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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.util.Assert;

import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;

/**
 * An {@link AuthenticationProvider} implementation for PAT Token Introspection.
 */
public final class PatTokenIntrospectionAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());

	private final PatAuthorizationService authorizationService;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationProvider} using the
	 * provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public PatTokenIntrospectionAuthenticationProvider(PatAuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		PatTokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = (PatTokenIntrospectionAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(tokenIntrospectionAuthentication);

		PatAuthorization authorization = this.authorizationService.find(tokenIntrospectionAuthentication.getToken());
		if (authorization == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Did not authenticate pat introspection request since token was not found");
			}
			// Return the authentication request when token not found
			return tokenIntrospectionAuthentication;
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with token");
		}

		if (!validate(authorization)) {
			return tokenIntrospectionAuthentication;
		}

		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		PatTokenIntrospection tokenClaims = PatTokenIntrospection.builder(true)
			.scopes(scopes -> {
				scopes.addAll(authorizedScopes);
			})
			.username(authorization.getPrincipalName())
			.issuedAt(authorization.getIssuedAt())
			.expiresAt(authorization.getExpiresAt())
			.notBefore(authorization.getNotBefore())
			.build();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated token introspection request");
		}

		return new PatTokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
				clientPrincipal, tokenClaims);
	}

	private boolean validate(PatAuthorization patAuthorization) {
		Clock clock = Clock.systemUTC();
		Duration clockSkew = Duration.of(60, ChronoUnit.SECONDS);
		Instant expiry = patAuthorization.getExpiresAt();
		if (expiry != null) {
			if (Instant.now(clock).minus(clockSkew).isAfter(expiry)) {
				return false;
			}
		}
		Instant before = patAuthorization.getNotBefore();
		if (before != null) {
			if (Instant.now(clock).plus(clockSkew).isBefore(before)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PatTokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
	}

}

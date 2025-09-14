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

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.jvalkeal.secpat.pat.PatAuthenticationException;

/**
 * A {@code Filter} for the PAT Token Introspection endpoint.
 *
 * @author Janne Valkealahti
 */
public final class PatTokenIntrospectionEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for token introspection requests.
	 */
	private static final String DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI = "/pat/introspect";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher tokenIntrospectionEndpointMatcher;

	private AuthenticationConverter authenticationConverter;

	private final HttpMessageConverter<PatTokenIntrospection> tokenIntrospectionHttpResponseConverter = new PatTokenIntrospectionHttpMessageConverter();

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendIntrospectionResponse;

	private AuthenticationFailureHandler authenticationFailureHandler = new PatErrorAuthenticationFailureHandler();

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 */
	public PatTokenIntrospectionEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 * @param tokenIntrospectionEndpointUri the endpoint {@code URI} for token
	 * introspection requests
	 */
	public PatTokenIntrospectionEndpointFilter(AuthenticationManager authenticationManager,
			String tokenIntrospectionEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenIntrospectionEndpointUri, "tokenIntrospectionEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.tokenIntrospectionEndpointMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, tokenIntrospectionEndpointUri);
		this.authenticationConverter = new PatTokenIntrospectionAuthenticationConverter();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenIntrospectionEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication tokenIntrospectionAuthentication = this.authenticationConverter.convert(request);
			Authentication tokenIntrospectionAuthenticationResult = this.authenticationManager
				.authenticate(tokenIntrospectionAuthentication);
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					tokenIntrospectionAuthenticationResult);
		}
		catch (PatAuthenticationException ex) {
			SecurityContextHolder.clearContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Token introspection request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an
	 * Introspection Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2TokenIntrospectionAuthenticationToken} used for authenticating the
	 * request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract an Introspection Request from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2TokenIntrospectionAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Resonse}.
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used
	 * for handling an {@link OAuth2AuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	private void sendIntrospectionResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		PatTokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = (PatTokenIntrospectionAuthenticationToken) authentication;
		PatTokenIntrospection tokenClaims = tokenIntrospectionAuthentication.getTokenClaims();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.tokenIntrospectionHttpResponseConverter.write(tokenClaims, null, httpResponse);
	}

}

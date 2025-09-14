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

package com.github.jvalkeal.secpat.pat;

import java.io.IOException;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.jvalkeal.secpat.pat.resolver.DefaultPatTokenResolver;
import com.github.jvalkeal.secpat.pat.resolver.PatTokenResolver;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class PatTokenAuthenticationFilter extends OncePerRequestFilter {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();
	private AuthenticationManager authenticationManager;
	private PatTokenResolver patResolver = new DefaultPatTokenResolver();
	private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

	public PatTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		try {
			String token = this.patResolver.resolve(request);
			if (token == null) {
				this.logger.trace("Did not process authentication request since failed to find "
						+ "PAT from a request");
				chain.doFilter(request, response);
				return;
			}
			PatTokenAuthenticationToken authRequest = PatTokenAuthenticationToken.unauthenticated(token);
			Authentication authResult = this.authenticationManager.authenticate(authRequest);
			SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
			context.setAuthentication(authResult);
			this.securityContextHolderStrategy.setContext(context);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
			}
			this.securityContextRepository.saveContext(context, request, response);

			// // 	onSuccessfulAuthentication(request, response, authResult);
		} catch (AuthenticationException ex) {
			this.securityContextHolderStrategy.clearContext();
			this.logger.debug("Failed to process authentication request", ex);
			// onUnsuccessfulAuthentication(request, response, ex);
				chain.doFilter(request, response);
			return;
		}
		chain.doFilter(request, response);
	}

	protected boolean authenticationIsRequired(String username) {
		// Authentication existingAuth = this.securityContextHolderStrategy.getContext().getAuthentication();
		// if (existingAuth == null || !existingAuth.getName().equals(username) || !existingAuth.isAuthenticated()) {
		// 	return true;
		// }
		// return (existingAuth instanceof AnonymousAuthenticationToken);
		return true;
	}


}

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

package com.github.jvalkeal.secpat.pat.resolver;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import jakarta.servlet.http.HttpServletRequest;

public final class DefaultPatTokenResolver implements PatTokenResolver {

	private static final Pattern authorizationPattern = Pattern.compile("^(?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private String apiKeyHeaderName = "X-Pat";

	@Override
	public String resolve(HttpServletRequest request) {
		final String authorizationHeaderToken = resolveFromAuthorizationHeader(request);
		if (authorizationHeaderToken != null) {
			return authorizationHeaderToken;
		}
		return null;
	}

	private String resolveFromAuthorizationHeader(HttpServletRequest request) {
		String authorization = request.getHeader(this.apiKeyHeaderName);
		if (authorization == null) {
			return null;
		}
		// if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
		// 	return null;
		// }
		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			// BearerTokenError error = BearerTokenErrors.invalidToken("Api Key is malformed");
			throw new OAuth2AuthenticationException("Api Key is malformed");
		}
		return matcher.group("token");
	}

}

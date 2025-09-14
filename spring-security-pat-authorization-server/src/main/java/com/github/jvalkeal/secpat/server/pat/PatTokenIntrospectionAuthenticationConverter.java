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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import com.github.jvalkeal.secpat.pat.PatAuthenticationException;
import com.github.jvalkeal.secpat.pat.PatError;
import com.github.jvalkeal.secpat.pat.PatErrorCodes;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Attempts to extract an Introspection Request from {@link HttpServletRequest} and then
 * converts it to an {@link PatTokenIntrospectionAuthenticationProvider} used for
 * authenticating the request.
 *
 * @see AuthenticationConverter
 * @see PatTokenIntrospectionAuthenticationToken
 * @see PatTokenIntrospectionEndpointFilter
 */
public final class PatTokenIntrospectionAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		// ^^^ is OAuth2ClientAuthenticationToken
		MultiValueMap<String, String> parameters = PatEndpointUtils.getFormParameters(request);

		// token (REQUIRED)
		String token = parameters.getFirst(PatParameterNames.TOKEN);
		if (!StringUtils.hasText(token) || parameters.get(PatParameterNames.TOKEN).size() != 1) {
			throwError(PatErrorCodes.INVALID_REQUEST, PatParameterNames.TOKEN);
		}

		// token_type_hint (OPTIONAL)
		String tokenTypeHint = parameters.getFirst(PatParameterNames.TOKEN_TYPE_HINT);
		if (StringUtils.hasText(tokenTypeHint) && parameters.get(PatParameterNames.TOKEN_TYPE_HINT).size() != 1) {
			throwError(PatErrorCodes.INVALID_REQUEST, PatParameterNames.TOKEN_TYPE_HINT);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(PatParameterNames.TOKEN) && !key.equals(PatParameterNames.TOKEN_TYPE_HINT)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		return new PatTokenIntrospectionAuthenticationToken(token, clientPrincipal, tokenTypeHint,
				additionalParameters);
	}

	private static void throwError(String errorCode, String parameterName) {
		PatError error = new PatError(errorCode, "Pat Introspection Parameter: " + parameterName);
		throw new PatAuthenticationException(error);
	}

}

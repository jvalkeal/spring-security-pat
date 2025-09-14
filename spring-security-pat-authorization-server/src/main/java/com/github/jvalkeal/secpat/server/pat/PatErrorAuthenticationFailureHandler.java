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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;

import com.github.jvalkeal.secpat.pat.PatAuthenticationException;
import com.github.jvalkeal.secpat.pat.PatError;

/**
 * An implementation of an {@link AuthenticationFailureHandler} used for handling an
 * {@link PatAuthenticationException} and returning the {@link PatError Pat
 * Error Response}.
 *
 */
public final class PatErrorAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private HttpMessageConverter<PatError> errorResponseConverter = new PatErrorHttpMessageConverter();

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException, ServletException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);

		if (authenticationException instanceof PatAuthenticationException oauth2AuthenticationException) {
			PatError error = oauth2AuthenticationException.getError();
			this.errorResponseConverter.write(error, null, httpResponse);
		}
		else {
			if (this.logger.isWarnEnabled()) {
				this.logger.warn(AuthenticationException.class.getSimpleName() + " must be of type "
						+ PatAuthenticationException.class.getName() + " but was "
						+ authenticationException.getClass().getName());
			}
		}
	}

	/**
	 * Sets the {@link HttpMessageConverter} used for converting an {@link OAuth2Error} to
	 * an HTTP response.
	 * @param errorResponseConverter the {@link HttpMessageConverter} used for converting
	 * an {@link OAuth2Error} to an HTTP response
	 */
	public void setErrorResponseConverter(HttpMessageConverter<PatError> errorResponseConverter) {
		Assert.notNull(errorResponseConverter, "errorResponseConverter cannot be null");
		this.errorResponseConverter = errorResponseConverter;
	}

}

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

import java.io.Serial;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * This exception is thrown for all Pat related {@link Authentication} errors.
 *
 */
public class PatAuthenticationException extends AuthenticationException {

	@Serial
	private static final long serialVersionUID = -7832130893085581438L;

	private final PatError error;

	/**
	 * Constructs an {@code PatAuthenticationException} using the provided parameters.
	 *
	 * @param errorCode the {@link PatErrorCodes Pat Error Code}
	 */
	public PatAuthenticationException(String errorCode) {
		this(new PatError(errorCode));
	}

	/**
	 * Constructs an {@code PatAuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link PatError Pat Error}
	 */
	public PatAuthenticationException(PatError error) {
		this(error, error.getDescription());
	}

	/**
	 * Constructs an {@code PatAuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link PatError Pat Error}
	 * @param cause the root cause
	 */
	public PatAuthenticationException(PatError error, Throwable cause) {
		this(error, cause.getMessage(), cause);
	}

	/**
	 * Constructs an {@code PatAuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link PatError Pat Error}
	 * @param message the detail message
	 */
	public PatAuthenticationException(PatError error, String message) {
		this(error, message, null);
	}

	/**
	 * Constructs an {@code PatAuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link PatError Pat Error}
	 * @param message the detail message
	 * @param cause the root cause
	 */
	public PatAuthenticationException(PatError error, String message, Throwable cause) {
		super(message, cause);
		Assert.notNull(error, "error cannot be null");
		this.error = error;
	}

	/**
	 * Returns the {@link PatError Pat Error}.
	 *
	 * @return the {@link PatError}
	 */
	public PatError getError() {
		return this.error;
	}

}

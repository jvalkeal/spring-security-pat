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

import org.springframework.util.Assert;

public class PatError {

	private final String errorCode;

	private final String description;

	/**
	 * Constructs an {@code PatError} using the provided parameters.
	 * @param errorCode the error code
	 */
	public PatError(String errorCode) {
		this(errorCode, null);
	}

	/**
	 * Constructs an {@code PatError} using the provided parameters.
	 * @param errorCode the error code
	 * @param description the error description
	 * @param uri the error uri
	 */
	public PatError(String errorCode, String description) {
		Assert.hasText(errorCode, "errorCode cannot be empty");
		this.errorCode = errorCode;
		this.description = description;
	}

	/**
	 * Returns the error code.
	 * @return the error code
	 */
	public final String getErrorCode() {
		return this.errorCode;
	}

	/**
	 * Returns the error description.
	 * @return the error description
	 */
	public final String getDescription() {
		return this.description;
	}

	@Override
	public String toString() {
		return "[" + this.getErrorCode() + "] " + ((this.getDescription() != null) ? this.getDescription() : "");
	}
}

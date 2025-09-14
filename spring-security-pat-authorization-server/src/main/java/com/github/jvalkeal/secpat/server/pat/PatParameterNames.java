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

/**
 * Standard and custom (non-standard) parameter names used by the pat introspection endpoint.
 */
public final class PatParameterNames {

	/**
	 * {@code client_id} - used in Authorization Request and Access Token Request.
	 */
	public static final String CLIENT_ID = "client_id";

	/**
	 * {@code client_secret} - used in Access Token Request.
	 */
	public static final String CLIENT_SECRET = "client_secret";

	/**
	 * {@code scope} - used in Authorization Request, Authorization Response, Access Token
	 * Request and Access Token Response.
	 */
	public static final String SCOPE = "scope";

	/**
	 * {@code expires_in} - used in Authorization Response and Access Token Response.
	 */
	public static final String EXPIRES_IN = "expires_in";

	/**
	 * {@code username} - used in Access Token Request.
	 */
	public static final String USERNAME = "username";

	/**
	 * {@code password} - used in Access Token Request.
	 */
	public static final String PASSWORD = "password";

	/**
	 * {@code error} - used in Authorization Response and Access Token Response.
	 */
	public static final String ERROR = "error";

	/**
	 * {@code error_description} - used in Authorization Response and Access Token
	 * Response.
	 */
	public static final String ERROR_DESCRIPTION = "error_description";

	/**
	 * Non-standard parameter (used internally).
	 */
	public static final String REGISTRATION_ID = "registration_id";

	/**
	 * {@code token} - used in Token Revocation Request.
	 * @since 5.5
	 */
	public static final String TOKEN = "token";

	/**
	 * {@code token_type_hint} - used in Token Revocation Request.
	 * @since 5.5
	 */
	public static final String TOKEN_TYPE_HINT = "token_type_hint";

	private PatParameterNames() {
	}

}

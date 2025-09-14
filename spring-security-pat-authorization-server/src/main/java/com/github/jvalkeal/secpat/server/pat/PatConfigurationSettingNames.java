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

public final class PatConfigurationSettingNames {

	private static final String SETTINGS_NAMESPACE = "settings.";

	private PatConfigurationSettingNames() {
	}

	/**
	 * The names for authorization server configuration settings.
	 */
	public static final class PatAuthorizationServer {

		private static final String AUTHORIZATION_SERVER_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE
			.concat("pat-authorization-server.");

		/**
		 * Set the Pat Token Introspection endpoint.
		 */
		public static final String TOKEN_INTROSPECTION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("token-introspection-endpoint");

		private PatAuthorizationServer() {
		}

	}

}

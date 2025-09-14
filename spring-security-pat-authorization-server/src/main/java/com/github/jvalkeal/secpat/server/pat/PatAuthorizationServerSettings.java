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

import java.util.Map;

import org.springframework.security.oauth2.server.authorization.settings.AbstractSettings;
import org.springframework.util.Assert;

/**
 * A facility for pat authorization server configuration settings.
 *
 * @see AbstractSettings
 * @see PatConfigurationSettingNames.PatAuthorizationServer
 */
public final class PatAuthorizationServerSettings extends AbstractSettings {

	private PatAuthorizationServerSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns the Pat Token Introspection endpoint. The default is
	 * {@code /pat/introspect}.
	 *
	 * @return the Token Introspection endpoint
	 */
	public String getTokenIntrospectionEndpoint() {
		return getSetting(PatConfigurationSettingNames.PatAuthorizationServer.TOKEN_INTROSPECTION_ENDPOINT);
	}

	/**
	 * Constructs a new {@link Builder} with the default settings.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder()
			.tokenIntrospectionEndpoint("/pat/introspect");
	}

	/**
	 * Constructs a new {@link Builder} with the provided settings.
	 *
	 * @param settings the settings to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withSettings(Map<String, Object> settings) {
		Assert.notEmpty(settings, "settings cannot be empty");
		return new Builder().settings((s) -> s.putAll(settings));
	}

	/**
	 * A builder for {@link PatAuthorizationServerSettings}.
	 */
	public static final class Builder extends AbstractBuilder<PatAuthorizationServerSettings, Builder> {

		private Builder() {
		}

		/**
		 * Sets the Pat Token Introspection endpoint.
		 *
		 * @param tokenIntrospectionEndpoint the Token Introspection endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
			return setting(PatConfigurationSettingNames.PatAuthorizationServer.TOKEN_INTROSPECTION_ENDPOINT,
					tokenIntrospectionEndpoint);
		}

		/**
		 * Builds the {@link PatAuthorizationServerSettings}.
		 *
		 * @return the {@link PatAuthorizationServerSettings}
		 */
		@Override
		public PatAuthorizationServerSettings build() {
			PatAuthorizationServerSettings authorizationServerSettings = new PatAuthorizationServerSettings(getSettings());
			return authorizationServerSettings;
		}

	}

}

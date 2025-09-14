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

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@ExtendWith(SpringTestContextExtension.class)
class PatIntrospectionTests {

	public final SpringTestContext spring = new SpringTestContext();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	@Test
	void test1() {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// MvcResult mvcResult = this.mvc.perform(post(this.authorizationServerSettings.getTokenIntrospectionEndpoint())
		// 		.params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
		// 		.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
		// 		.andExpect(status().isOk())
		// 		.andReturn();

	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		public RegisteredClientRepository registeredClientRepository() {
			RegisteredClient oidcClient1 = RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId("oidc-client")
					.clientSecret("{noop}secret")
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.redirectUri("http://apiserver:8080/login/oauth2/code/oidc-client")
					.postLogoutRedirectUri("http://apiserver:8080/")
					.scope(OidcScopes.OPENID)
					.scope(OidcScopes.PROFILE)
					.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
					.build();
			return new InMemoryRegisteredClientRepository(oidcClient1);
		}


	}
}

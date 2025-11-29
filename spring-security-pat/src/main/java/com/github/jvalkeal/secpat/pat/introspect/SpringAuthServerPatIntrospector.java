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

package com.github.jvalkeal.secpat.pat.introspect;

import java.io.Serial;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.github.jvalkeal.secpat.pat.PatAuthenticatedPrincipal;

/**
 * {@link PatIntrospector} implementation able to use Spring Authorization
 * Server's PAT introspection endpoint.
 *
 * Essentially this is a facade to talk to {@link PatAuthorizationServicePatIntrospector}
 * running within a Spring Authorization Server.
 *
 * @author Janne Valkealahti
 */
public class SpringAuthServerPatIntrospector implements PatIntrospector {

	private final Log logger = LogFactory.getLog(getClass());

	private final RestOperations restOperations;

	private Converter<String, RequestEntity<?>> requestEntityConverter;

	private Converter<PatTokenIntrospectionClaimAccessor, ? extends PatAuthenticatedPrincipal> authenticationConverter = this::defaultAuthenticationConverter;

	public SpringAuthServerPatIntrospector(String introspectionUri, RestOperations restOperations) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.requestEntityConverter = this.defaultRequestEntityConverter(URI.create(introspectionUri));
		this.restOperations = restOperations;
	}

	private Converter<String, RequestEntity<?>> defaultRequestEntityConverter(URI introspectionUri) {
		return (token) -> {
			HttpHeaders headers = requestHeaders();
			MultiValueMap<String, String> body = requestBody(token);
			return new RequestEntity<>(body, headers, HttpMethod.POST, introspectionUri);
		};
	}

	private PatAuthenticatedPrincipal defaultAuthenticationConverter(
			PatTokenIntrospectionClaimAccessor accessor) {
		Collection<GrantedAuthority> authorities = authorities(accessor.getScopes());
		return PatAuthenticatedPrincipal.of(accessor.getClaimAsString(PatTokenIntrospectionClaimNames.USERNAME), authorities);
	}

	private Collection<GrantedAuthority> authorities(List<String> scopes) {
		// vvv ArrayList vs ArrayListFromSpring, bug in spring-security???
		// if (!(scopes instanceof ArrayListFromString)) {
		// 	return Collections.emptyList();
		// }
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		for (String scope : scopes) {
			authorities.add(new SimpleGrantedAuthority(scope));
		}
		return authorities;
	}

	private HttpHeaders requestHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		return headers;
	}

	private MultiValueMap<String, String> requestBody(String token) {
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("token", token);
		return body;
	}

	@Override
	public PatAuthenticatedPrincipal introspect(String token) {
		RequestEntity<?> requestEntity = this.requestEntityConverter.convert(token);
		if (requestEntity == null) {
			throw new PatIntrospectionException("requestEntityConverter returned a null entity");
		}
		ResponseEntity<Map<String, Object>> responseEntity = makeRequest(requestEntity);
		Map<String, Object> claims = adaptToNimbusResponse(responseEntity);
		PatTokenIntrospectionClaimAccessor accessor = convertClaimsSet(claims);
		return this.authenticationConverter.convert(accessor);
	}

	private Map<String, Object> adaptToNimbusResponse(ResponseEntity<Map<String, Object>> responseEntity) {
		if (responseEntity.getStatusCode() != HttpStatus.OK) {
			throw new PatIntrospectionException(
					"Introspection endpoint responded with " + responseEntity.getStatusCode());
		}
		Map<String, Object> claims = responseEntity.getBody();
		// relying solely on the authorization server to validate this token (not checking
		// 'exp', for example)
		if (claims == null) {
			return Collections.emptyMap();
		}

		boolean active = (boolean) claims.compute(PatTokenIntrospectionClaimNames.ACTIVE, (k, v) -> {
			if (v instanceof String) {
				return Boolean.parseBoolean((String) v);
			}
			if (v instanceof Boolean) {
				return v;
			}
			return false;
		});
		if (!active) {
			this.logger.trace("Did not validate token since it is inactive");
			throw new PatIntrospectionException("Provided token isn't active");
		}
		return claims;
	}

	private ArrayListFromStringClaimAccessor convertClaimsSet(Map<String, Object> claims) {
		Map<String, Object> converted = new LinkedHashMap<>(claims);
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.AUD, (k, v) -> {
			if (v instanceof String) {
				return Collections.singletonList(v);
			}
			return v;
		});
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.CLIENT_ID, (k, v) -> v.toString());
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.EXP,
				(k, v) -> Instant.ofEpochSecond(((Number) v).longValue()));
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.IAT,
				(k, v) -> Instant.ofEpochSecond(((Number) v).longValue()));
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.ISS, (k, v) -> v.toString());
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.NBF,
				(k, v) -> Instant.ofEpochSecond(((Number) v).longValue()));
		converted.computeIfPresent(PatTokenIntrospectionClaimNames.SCOPE,
				(k, v) -> (v instanceof String s) ? new ArrayListFromString(s.split(" ")) : v);
		return () -> converted;
	}

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private ResponseEntity<Map<String, Object>> makeRequest(RequestEntity<?> requestEntity) {
		try {
			return this.restOperations.exchange(requestEntity, STRING_OBJECT_MAP);
		}
		catch (Exception ex) {
			throw new PatIntrospectionException(ex.getMessage(), ex);
		}
	}

	private static final class ArrayListFromString extends ArrayList<String> {

		@Serial
		private static final long serialVersionUID = -1804103555781637109L;

		ArrayListFromString(String... elements) {
			super(Arrays.asList(elements));
		}

	}

	private interface ArrayListFromStringClaimAccessor extends PatTokenIntrospectionClaimAccessor {

		@Override
		default List<String> getScopes() {
			Object value = getClaims().get(PatTokenIntrospectionClaimNames.SCOPE);
			if (value instanceof ArrayListFromString list) {
				return list;
			}
			return PatTokenIntrospectionClaimAccessor.super.getScopes();
		}

	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {

		private String introspectionUri;

		private String clientId;

		private String clientSecret;

		public Builder introspectionUri(String introspectionUri) {
			Assert.notNull(introspectionUri, "introspectionUri cannot be null");
			this.introspectionUri = introspectionUri;
			return this;
		}

		public Builder clientId(String clientId) {
			Assert.notNull(clientId, "clientId cannot be null");
			this.clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
			return this;
		}

		public Builder clientSecret(String clientSecret) {
			Assert.notNull(clientSecret, "clientSecret cannot be null");
			this.clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
			return this;
		}

		public SpringAuthServerPatIntrospector build() {
			RestTemplate restTemplate = new RestTemplate();
			restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(this.clientId, this.clientSecret));
			return new SpringAuthServerPatIntrospector(this.introspectionUri, restTemplate);
		}

	}
}

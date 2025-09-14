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

package com.github.jvalkeal.secpat.autoconfigure;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.util.StringUtils;

import com.github.jvalkeal.secpat.autoconfigure.PatProperties.Pat;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;

/**
 * Maps {@link PatProperties} to {@link PatAuthorization PatAuthorizations}.
 *
 */
public final class PatPatsPropertiesMapper {

	private final PatProperties properties;

	/**
	 * Creates a new mapper for the given {@code properties}.
	 * @param properties the properties to map
	 */
	public PatPatsPropertiesMapper(PatProperties properties) {
		this.properties = properties;
	}

	/**
	 * Maps the properties to {@link PatAuthorization PatAuthorizations}.
	 * @return the mapped {@code PatAuthorizations}
	 */
	public List<PatAuthorization> asPatAuthorizations() {
		return properties.getPats().stream().map(pat -> getPatAuthorization(pat)).collect(Collectors.toList());
	}

	private static PatAuthorization getPatAuthorization(Pat pat) {
		String principalName = pat.getPrincipal();
		String token = pat.getToken();
		Set<String> scopes = pat.getScopes();
		Instant issuedAt = pat.getIssuedAt();
		Instant expiresAt = pat.getExpiresAt();
		Instant notBefore = pat.getNotBefore();
		if (!StringUtils.hasText(principalName)) {
			throw new IllegalStateException("Principal must be specified for pat");
		}
		return new PatAuthorization(principalName, scopes, token, issuedAt, expiresAt, notBefore);
	}

}

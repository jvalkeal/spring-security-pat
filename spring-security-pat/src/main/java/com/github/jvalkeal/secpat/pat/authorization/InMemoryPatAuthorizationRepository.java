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

package com.github.jvalkeal.secpat.pat.authorization;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.util.ObjectUtils;

/**
 * In-Memory implementation of a {@link PatAuthorizationRepository}.
 *
 * @author Janne Valkealahti
 */
public class InMemoryPatAuthorizationRepository implements PatAuthorizationRepository {

	private Map<String, PatAuthorization> authorizations = new ConcurrentHashMap<>();

	@Override
	public void save(PatAuthorization authorization) {
		if (findByToken(authorization.getToken()) != null) {
			throw new IllegalArgumentException("Can't save with existing same token");
		}
		authorizations.put(authorization.getToken(), authorization);
	}

	@Override
	public void remove(PatAuthorization authorization) {
		authorizations.remove(authorization.getToken());
	}

	@Override
	public PatAuthorization findById(String id) {
		return authorizations.values().stream()
			.filter(pa -> ObjectUtils.nullSafeEquals(pa.getId(), id))
			.findFirst()
			.orElse(null);
	}

	@Override
	public PatAuthorization findByToken(String token) {
		return authorizations.get(token);
	}

	@Override
	public List<PatAuthorization> findByPrincipal(String principal) {
		return authorizations.values().stream()
			.filter(pa -> ObjectUtils.nullSafeEquals(pa.getPrincipal(), principal))
			.collect(Collectors.toList());
	}

}

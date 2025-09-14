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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.github.jvalkeal.secpat.pat.keygen.PatGenerationService;

/**
 * In-Memory implementation of a {@link PatAuthorizationService}.
 *
 * This implementation is just for testing and demos and should
 * not be used in a production.
 *
 * @author Janne Valkealahti
 */
public class InMemoryPatAuthorizationService implements PatAuthorizationService {

	private Map<String, PatAuthorization> authorizations = new ConcurrentHashMap<>();

	// private PatGenerationService patGenerationService;

	// public InMemoryPatAuthorizationService() {
	// }

	// public InMemoryPatAuthorizationService(PatGenerationService patGenerationService) {
	// 	this.patGenerationService = patGenerationService;
	// }

	@Override
	public void save(PatAuthorization authorization) {
		authorizations.put(authorization.getToken(), authorization);
	}

	@Override
	public void remove(PatAuthorization authorization) {
		authorizations.remove(authorization.getToken());
	}

	@Override
	public PatAuthorization find(String token) {
		// if (patGenerationService != null) {
		// 	boolean validated = patGenerationService.validate(token);
		// 	if (!validated) {
		// 		return null;
		// 	}
		// }
		return authorizations.get(token);
	}

}

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

/**
 * Service store keeping relationship between a PAT token
 * and {@link PatAuthorization}.
 *
 * @author Janne Valkealahti
 * @see InMemoryPatAuthorizationService
 */
public interface PatAuthorizationService {

	/**
	 * Save a {@link PatAuthorization}.
	 *
	 * @param authorization the pat authorization
	 */
	void save(PatAuthorization authorization);

	/**
	 * Remove a {@link PatAuthorization}.
	 *
	 * @param authorization the pat authorization
	 */
	void remove(PatAuthorization authorization);

	/**
	 * Find a {@link PatAuthorization} with given PAT token.
	 *
	 * @param token the pat token
	 * @return a pat authorization
	 */
	PatAuthorization find(String token);

	PatAuthorization findById(String id);
	List<PatAuthorization> findByPrincipal(String principal);
}

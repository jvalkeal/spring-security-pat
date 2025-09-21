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
 * Repository interface storing {@link PatAuthorization}s.
 *
 * @author Janne Valkealahti
 */
public interface PatAuthorizationRepository {

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
	 * Find a {@link PatAuthorization} with given id.
	 *
	 * @param id the id
	 * @return a pat authorization
	 */
	PatAuthorization findById(String id);

	/**
	 * Find a {@link PatAuthorization} with given token.
	 *
	 * @param token the token
	 * @return a pat authorization
	 */
	PatAuthorization findByToken(String token);

	/**
	 * Find a {@link PatAuthorization}s with given principal.
	 *
	 * @param principal the principal
	 * @return a pat authorizations
	 */
	List<PatAuthorization> findByPrincipal(String principal);

}

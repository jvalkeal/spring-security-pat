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

import org.springframework.util.Assert;

/**
 * {@link PatAuthorizationService} using {@link PatAuthorizationRepository}.
 *
 * @author Janne Valkealahti
 */
public class RepositoryPatAuthorizationService implements PatAuthorizationService {

	private final PatAuthorizationRepository repository;

	public RepositoryPatAuthorizationService(PatAuthorizationRepository repository) {
		Assert.notNull(repository, "repository must be set");
		this.repository = repository;
	}

	@Override
	public PatAuthorization acquire(AcquireContext context) {
		return repository.findByToken(context.token());
	}

}

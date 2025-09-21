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

package com.github.jvalkeal.secpat.pat.keygen;

/**
 * {@code PatGenerationService} works in two ways, firstly it can create a new
 * {@code PAT} token and secondly it can validate if {@code PAT} token can ever
 * be a valid.
 *
 * {@code PAT} validation from this service is not an actual authorization check
 * and simply validates to skip false positives order to skip token which
 * would never be valid.
 *
 * @author Janne Valkealahti
 * @see OrgPrefixPatGenerationService
 */
public interface PatGenerationService {

	/**
	 * Generate a {@code PAT}.
	 *
	 * @return a generated {@code PAT}
	 */
	String generate(Object source);

	/**
	 * Validate {@code PAT} to be able to skip false positives.
	 *
	 * @param pat a PAT
	 * @return {@code TRUE} if pat is valid
	 */
	boolean validate(String pat);

}

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

/**
 * Service store keeping relationship between a PAT token
 * and {@link PatAuthorization}.
 *
 * @author Janne Valkealahti
 * @see InMemoryPatAuthorizationService
 */
public interface PatAuthorizationService {

	/**
	 * Acquire a {@link PatAuthorization} with given context.
	 *
	 * @param context the context
	 * @return a pat authorization
	 */
	PatAuthorization acquire(AcquireContext context);

	/**
	 * Context interface used with acquiring pat authorization.
	 */
	interface AcquireContext {

		/**
		 * A token associated with this context
		 * @return the token
		 */
		String token();

		/**
		 * Build context out from a token.
		 *
		 * @param token the token
		 * @return a context
		 */
		static AcquireContext ofToken(String token) {
			return new AcquireContext() {

				@Override
				public String token() {
					return token;
				}
			};
		}
	}
}

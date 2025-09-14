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

import com.github.jvalkeal.secpat.pat.PatAuthenticatedPrincipal;

/**
 * A contract for introspecting and verifying a PAT token.
 *
 * A typical implementation of this interface will make a request to an
 * Spring Authorization Server PAt Introspection Endpoint to verify the
 * token and return its attributes, indicating a successful verification.
 *
 * @author Janne Valkealahti
 */
@FunctionalInterface
public interface PatIntrospector {

	/**
	 * Introspect and verify the given token, returning its attributes.
	 *
	 * Returning a {@link PatAuthenticatedPrincipal} is indicative that the token is
	 * valid.
	 *
	 * @param token the token to introspect
	 * @return the token's attributes
	 */
	PatAuthenticatedPrincipal introspect(String token);

}

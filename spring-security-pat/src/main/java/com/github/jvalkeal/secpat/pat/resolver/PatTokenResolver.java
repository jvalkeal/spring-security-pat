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

package com.github.jvalkeal.secpat.pat.resolver;

import com.github.jvalkeal.secpat.pat.PatAuthenticationException;

import jakarta.servlet.http.HttpServletRequest;

/**
 * A strategy for resolving {@code PAT} from a request.
 *
 * @author Janne Valkealahti
 */
@FunctionalInterface
public interface PatTokenResolver {

	/**
	 * Resolve any {@code PAT} value from the request.
	 *
	 * @param request the request
	 * @return the PAT value or {@code null} if none found
	 * @throws PatAuthenticationException if the found token is invalid
	 */
	String resolve(HttpServletRequest request);

}

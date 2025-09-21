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

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.zip.CRC32;

import org.springframework.util.Assert;

/**
 * Default implementation of a {@link PatGenerationService}.
 *
 * @author Janne Valkealahti
 */
public final class OrgPrefixPatGenerationService implements PatGenerationService, PatService {

	private static final String BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final String PAT_FORMAT = "%s_%s_%s_%s";
	private static final String PAT_FORMAT_VERSION = "%s_%s_%s_%s_%s";
	private final String org;
	private final String type;
	private final int length;
	private final String version;

	public OrgPrefixPatGenerationService(String org, String type, int length) {
		this(org, type, length, null);
	}

	public OrgPrefixPatGenerationService(String org, String type, int length, String version) {
		Assert.hasText(org, "org must have a value");
		Assert.hasText(type, "type must have a value");
		Assert.isTrue(length > 50, "length must be higher than 50");
		this.org = org;
		this.type = type;
		this.length = length;
		this.version = version;
	}

	@Override
	public PatGenerator generator() {
		return (source) -> {
			return generate(source);
		};
	}

	@Override
	public PatMatcher matcher() {
		return (token) -> {
			return validate(token);
		};
	}

	@Override
	public String generate(Object source) {
		return generatePat(org, type, length, version);
	}

	@Override
	public boolean validate(String pat) {
		if (pat == null) {
			return false;
		}
		String[] fields = pat.split("_");
		if (fields.length != 4) {
			return false;
		}
		if (!fields[0].equals(org)) {
			return false;
		}
		if (!fields[1].equals(type)) {
			return false;
		}
		if (checksum(fields[3]).equals(fields[2])) {
			return true;
		}
		if (version != null && !fields[0].equals(version)) {
			return true;
		}
		return false;
	}

	private static String generatePat(String org, String type, int length, String version) {
		String rand = randomize(length, BASE62_CHARS);
		String enc = checksum(rand);
		if (version == null) {
			return String.format(PAT_FORMAT, org, type, enc, rand);
		}
		else {
			return String.format(PAT_FORMAT_VERSION, org, type, enc, rand, version);
		}
	}

	private static String checksum(String data) {
		CRC32 crc = new CRC32();
		ByteBuffer buf = ByteBuffer.allocate(data.length());
		buf.put(data.getBytes());
		crc.update(buf.array());
		return base62Encode(crc.getValue());
	}

	private static String randomize(int n, String chars) {
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < n; i++) {
			buf.append(chars.charAt(RANDOM.nextInt(chars.length())));
		}
		return buf.toString();
	}

	private static String base62Encode(long l) {
		final int base = 62;
		StringBuilder buf = new StringBuilder(1);
		do {
			buf.insert(0, BASE62_CHARS.charAt((int) (l % base)));
			l /= base;
		} while (l > 0);
		return buf.toString();
	}

}

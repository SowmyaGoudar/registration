package io.mosip.registration.processor.stages.legacy.data.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.springframework.stereotype.Component;

import io.mosip.kernel.core.util.CryptoUtil;
import lombok.Data;

@Component
@Data
public class LegacyDataApiUtility {

	public byte[] generateNonce() {
		SecureRandom random = new SecureRandom();
		byte[] nonce = new byte[16];
		random.nextBytes(nonce);
		return nonce;
	}

	public String generateDigest(byte[] nonce, byte[] created, byte[] passwordHash) throws NoSuchAlgorithmException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] combined = new byte[nonce.length + created.length + passwordHash.length];
		System.arraycopy(nonce, 0, combined, 0, nonce.length);
		System.arraycopy(created, 0, combined, nonce.length, created.length);
		System.arraycopy(passwordHash, 0, combined, nonce.length + created.length, passwordHash.length);
		return CryptoUtil.encodeToPlainBase64(sha1.digest(combined));
	}

	public String createTimestamp() {
		ZonedDateTime utcNow = ZonedDateTime.now(ZoneId.of("UTC"));

		// Convert UTC time to East Africa Time (EAT)
		ZonedDateTime timeNow = utcNow.withZoneSameInstant(ZoneId.of("Africa/Kampala"));

		// Get the ISO 8601 formatted string of the EAT time
		DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
		String timeStamp = timeNow.format(formatter);
		String truncatedTimestamp = timeStamp.substring(0, timeStamp.length() - 10); // Trim milliseconds and timezone

		// Append the static timezone offset +03:00
		return truncatedTimestamp + "+03:00";
	}

	public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		return sha1.digest(password.getBytes());
	}
}

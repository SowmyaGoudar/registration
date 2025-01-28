package io.mosip.registration.processor.packet.storage.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
public class CertificateResponse {
	private String certificate;
	private String certSignRequest;
	private String issuedAt;
	private String expiryAt;
	private String timestamp;
}

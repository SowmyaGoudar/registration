package io.mosip.registration.processor.core.packet.dto;

import java.io.Serializable;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class PacketInfo implements Serializable {

	private String id;
	private String packetName;
	private String source;
	private String process;
	private String refId;
	private String schemaVersion;
	private String signature;
	private String encryptedHash;
	private String providerName;
	private String providerVersion;
	private String creationDate;
}

package io.mosip.registration.processor.core.packet.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class DocumentDto {

	private byte[] document;
	private String value;
	private String type;
	private String format;
}

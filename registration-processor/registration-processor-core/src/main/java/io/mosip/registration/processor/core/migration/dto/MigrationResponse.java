package io.mosip.registration.processor.core.migration.dto;

import java.io.Serializable;
import java.util.Map;

import io.mosip.registration.processor.core.packet.dto.DocumentDto;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class MigrationResponse implements Serializable {

	String rid;

	private Map<String, String> demographics;
	
	private Map<String, DocumentDto> documents;
}

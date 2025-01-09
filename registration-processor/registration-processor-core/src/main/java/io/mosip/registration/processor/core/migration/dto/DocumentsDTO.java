package io.mosip.registration.processor.core.migration.dto;

import java.io.Serializable;
import java.util.Map;

import io.mosip.registration.processor.core.packet.dto.DocumentDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DocumentsDTO implements Serializable
{

	private Map<String, DocumentDto> documents;

}

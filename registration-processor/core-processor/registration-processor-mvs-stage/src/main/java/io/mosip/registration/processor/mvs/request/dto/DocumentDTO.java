package io.mosip.registration.processor.mvs.request.dto;

import java.util.Map;

import io.mosip.registration.processor.packet.storage.dto.Document;
import lombok.Data;

@Data
public class DocumentDTO {
	private Map<String, Document> documents;
}

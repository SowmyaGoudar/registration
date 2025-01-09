package io.mosip.registration.processor.core.migration.dto;

import java.io.Serializable;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class MigrationResponse implements Serializable {

	private DemographicsDto demographics;
	
	private DocumentsDTO documents;
}

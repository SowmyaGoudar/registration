package io.mosip.registration.processor.core.migration.dto;

import java.io.Serializable;
import java.util.Map;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class DemographicsDto implements Serializable {

	private Map<String, String> fields;

}

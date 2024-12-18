package io.mosip.registration.processor.stages.legacy.data.dto;

import java.util.Map;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class Demographics {

	private Map<String, String> fields;
}

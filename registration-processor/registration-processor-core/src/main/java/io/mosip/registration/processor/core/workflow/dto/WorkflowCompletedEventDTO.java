package io.mosip.registration.processor.core.workflow.dto;

import java.util.Map;

import lombok.Data;

@Data
public class WorkflowCompletedEventDTO {
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new message DTO.
	 */
	public WorkflowCompletedEventDTO() {
		super();
	}

	/** The registration id. */
	private String instanceId;
	private String resultCode;
	private String workflowType;
	private String errorCode;
	private Map<String, String> notificationAttributes;
}

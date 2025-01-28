package io.mosip.registration.processor.packet.storage.dto;

import lombok.Data;

@Data
public class SecureZoneNotificationRequest {


	private String reg_type;


	    private String rid;


	    private boolean isValid;


	    private boolean internalError;

	    private String messageBusAddress;


	    private Integer retryCount;

	
	    private String tags;


	    private String lastHopTimestamp;

	    private String source;

	
	    private int iteration;

	    private String  workflowInstanceId;
}

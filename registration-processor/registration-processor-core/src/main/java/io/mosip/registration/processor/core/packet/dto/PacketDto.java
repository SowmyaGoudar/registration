package io.mosip.registration.processor.core.packet.dto;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import io.mosip.kernel.biometrics.entities.BiometricRecord;
import lombok.Data;
import lombok.EqualsAndHashCode;


@Data
@EqualsAndHashCode
public class PacketDto implements Serializable {

    private String id;
    private String additionalInfoReqId;
    private String refId;
    private boolean offlineMode;
    private String process;
    private String source;
    private String schemaVersion;
    private String schemaJson;
    private Map<String, String> fields;
    private Map<String, String> metaInfo;
	private Map<String, DocumentDto> documents;
    private List<Map<String, String>> audits;
    private Map<String, BiometricRecord> biometrics;

}


package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import lombok.Data;


@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPersonRequest {
	
	private String nationalId;
}
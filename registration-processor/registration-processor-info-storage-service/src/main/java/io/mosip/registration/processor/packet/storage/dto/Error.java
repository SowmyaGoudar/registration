package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Error {
	@XmlElement(name = "code")
	private String code;

	@XmlElement(name = "message")
	private String message;
}

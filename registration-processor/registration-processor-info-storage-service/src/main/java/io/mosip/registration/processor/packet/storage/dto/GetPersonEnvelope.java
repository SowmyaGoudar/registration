package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import lombok.Data;
@XmlRootElement(name = "Envelope", namespace = "http://schemas.xmlsoap.org/soap/envelope/")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPersonEnvelope {
	@XmlElement(name = "Header", namespace = "http://schemas.xmlsoap.org/soap/envelope/")
	private GetPersonHeader header;

	@XmlElement(name = "Body", namespace = "http://schemas.xmlsoap.org/soap/envelope/")
	private GetPersonBody body;
}
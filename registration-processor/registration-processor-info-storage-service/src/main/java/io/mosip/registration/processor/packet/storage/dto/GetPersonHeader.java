package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPersonHeader {
	@XmlElement(name = "UsernameToken", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	private GetPersonUsernameToken usernameToken;

	// Getters and setters
	public GetPersonUsernameToken getUsernameToken() {
		return usernameToken;
	}

	public void setUsernameToken(GetPersonUsernameToken usernameToken) {
		this.usernameToken = usernameToken;
	}
}

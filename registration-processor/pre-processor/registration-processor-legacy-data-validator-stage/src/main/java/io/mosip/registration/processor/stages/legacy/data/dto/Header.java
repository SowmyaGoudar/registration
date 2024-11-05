package io.mosip.registration.processor.stages.legacy.data.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Header {
	@XmlElement(name = "UsernameToken", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	private UsernameToken usernameToken;

	// Getters and setters
	public UsernameToken getUsernameToken() {
		return usernameToken;
	}

	public void setUsernameToken(UsernameToken usernameToken) {
		this.usernameToken = usernameToken;
	}
}

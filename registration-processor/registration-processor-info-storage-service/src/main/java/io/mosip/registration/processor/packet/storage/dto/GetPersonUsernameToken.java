package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

//UsernameToken class
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPersonUsernameToken {
	@XmlElement(name = "Username", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	private String username;

	@XmlElement(name = "Password", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	private GetPersonPassword password;

	@XmlElement(name = "Nonce", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	private String nonce;

	@XmlElement(name = "Created", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	private String created;

}
package io.mosip.registration.processor.stages.legacy.data.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

//Body class
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Body {
	@XmlElement(name = "verifyPerson", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private VerifyPerson verifyPerson;

	@XmlElement(name = "getPersonResponse", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private VerifyPersonResponse getPersonResponse;
}

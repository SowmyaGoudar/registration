package io.mosip.registration.processor.stages.legacy.data.val.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

//Body class
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Body {
	@XmlElement(name = "identifyPerson", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private IdentifyPerson identifyPerson;

	@XmlElement(name = "identifyPersonResponse", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private IdentifyPersonResponse identifyPersonResponse;
}

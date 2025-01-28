package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

//Body class
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPersonBody {

	@XmlElement(name = "getPerson", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private GetPerson getPerson;

	@XmlElement(name = "getPersonResponse", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private GetPersonResponse getPersonResponse;
}

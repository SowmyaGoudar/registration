package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class ChangePasswordBody {

	@XmlElement(name = "changePassword", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private ChangePassword changePassword;

	@XmlElement(name = "changePasswordResponse", namespace = "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/")
	private ChangePasswordResponse changePasswordResponse;
}

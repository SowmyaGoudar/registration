package io.mosip.registration.processor.stages.legacy.data.val.dto;

import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Person {
	@XmlElement(name = "nationalId")
	private String nationalId;

	@XmlElement(name = "scores")
	private List<Score> scores;
}

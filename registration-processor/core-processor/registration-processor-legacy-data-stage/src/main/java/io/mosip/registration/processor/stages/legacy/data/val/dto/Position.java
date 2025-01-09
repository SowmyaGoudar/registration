package io.mosip.registration.processor.stages.legacy.data.val.dto;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum Position {
	RIGHT_THUMB("Right Thumb", "01"), RIGHT_INDEXFINGER("Right IndexFinger", "02"),
	RIGHT_MIDDLEFINGER("Right MiddleFinger", "03"),
	RIGHT_RINGFINGER("Right RingFinger", "04"),
	RIGHT_LITTLEFINGER("Right LittleFinger", "05"),
	LEFT_THUMB("Left Thumb", "06"), LEFT_INDEXFINGER("Left IndexFinger", "07"),
	LEFT_MIDDLEFINGER("Left MiddleFinger", "08"), LEFT_RINGFINGER("Left RingFinger", "09"),
	LEFT_LITTLEFINGER("Left LittleFinger", "10");

	private String key;
	private String value;
	private static final Map<String, String> positionMap = Collections.unmodifiableMap(initializeMapping());

	private static Map<String, String> initializeMapping() {
		Map<String, String> failureMap = new HashMap<String, String>();
		for (Position s : Position.values()) {
			failureMap.put(s.key, s.value);
		}
		return failureMap;
	}

	Position(String key, String value) {
	       this.key = key;
	       this.value = value;
	 }

	public static String getValueFromKey(String key) {
		return positionMap.get(key);
	}

}

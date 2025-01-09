package io.mosip.registration.processor.core.packet.dto;

import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class PacketInfoResponse {

	List<PacketInfo> packetinfoList;

}

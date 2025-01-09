package io.mosip.registration.processor.mvs.service;

import io.mosip.registration.processor.core.queue.factory.MosipQueue;
import io.mosip.registration.processor.mvs.response.dto.MVSResponseDTO;

import org.springframework.stereotype.Service;

import io.mosip.registration.processor.core.abstractverticle.MessageDTO;

@Service
public interface MVSService {

	public boolean updatePacketStatus(MVSResponseDTO resp, String stageName, MosipQueue queue);

	public MessageDTO process(MessageDTO object, MosipQueue queue, String stageName);

	
	
}

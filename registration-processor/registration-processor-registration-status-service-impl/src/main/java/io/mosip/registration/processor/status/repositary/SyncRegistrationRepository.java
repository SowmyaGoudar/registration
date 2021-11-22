package io.mosip.registration.processor.status.repositary;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import io.mosip.kernel.core.dataaccess.spi.repository.BaseRepository;
import io.mosip.registration.processor.status.entity.BaseSyncRegistrationEntity;
import io.mosip.registration.processor.status.entity.RegistrationStatusEntity;
import io.mosip.registration.processor.status.entity.SyncRegistrationEntity;

@Repository
public interface SyncRegistrationRepository<T extends BaseSyncRegistrationEntity, E> extends BaseRepository<T, E> {

	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.registrationId =:regId and registrationList.registrationType =:regType")
	public List<SyncRegistrationEntity> getSyncRecordsByRegIdAndRegType(@Param("regId") String regId,
			@Param("regType") String regType);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.registrationId = :registrationId and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByRegistrationId(@Param("registrationId") String registrationId);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.packetId = :packetId and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByPacketId(@Param("packetId") String packetId);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.additionalInfoReqId = :additionalInfoReqId and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByAdditionalInfoReqId(@Param("additionalInfoReqId") String additionalInfoReqId);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.registrationId IN :registrationIds and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByRegistrationIds(@Param("registrationIds") List<String> registrationIds);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.packetId IN :packetIds and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByPacketIds(@Param("packetIds") List<String> packetIds);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.registrationId = :registrationId and registrationList.additionalInfoReqId = :additionalInfoReqId and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByRegistrationIdIdAndAdditionalInfoReqId(@Param("registrationId") String registrationId,@Param("additionalInfoReqId") String additionalInfoReqId);
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.registrationId = :registrationId and registrationList.registrationType = :registrationType and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByRegistrationIdIdAndRegType(@Param("registrationId") String registrationId,@Param("registrationType") String registrationType);
	
	
	@Query("SELECT registrationList FROM SyncRegistrationEntity registrationList WHERE registrationList.workflowInstanceId = :workflowInstanceId and registrationList.isDeleted =false ")
	public List<SyncRegistrationEntity> findByworkflowInstanceId(@Param("workflowInstanceId") String workflowInstanceId);

}
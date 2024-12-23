package io.mosip.registration.processor.stages.legacy.data.val.stage;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONTokener;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.registration.processor.core.abstractverticle.MessageDTO;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.code.ModuleName;
import io.mosip.registration.processor.core.code.RegistrationTransactionStatusCode;
import io.mosip.registration.processor.core.code.RegistrationTransactionTypeCode;
import io.mosip.registration.processor.core.common.rest.dto.ErrorDTO;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.constant.MappingJsonConstants;
import io.mosip.registration.processor.core.constant.ProviderStageName;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.DataMigrationException;
import io.mosip.registration.processor.core.exception.PacketManagerException;
import io.mosip.registration.processor.core.exception.ValidationFailedException;
import io.mosip.registration.processor.core.exception.util.PlatformSuccessMessages;
import io.mosip.registration.processor.core.http.RequestWrapper;
import io.mosip.registration.processor.core.http.ResponseWrapper;
import io.mosip.registration.processor.core.idrepo.dto.Documents;
import io.mosip.registration.processor.core.logger.LogDescription;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.migration.dto.DemographicsDto;
import io.mosip.registration.processor.core.migration.dto.DocumentsDTO;
import io.mosip.registration.processor.core.migration.dto.MigrationRequestDto;
import io.mosip.registration.processor.core.migration.dto.MigrationResponse;
import io.mosip.registration.processor.core.packet.dto.DocumentDto;
import io.mosip.registration.processor.core.packet.dto.PacketDto;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.core.util.JsonUtil;
import io.mosip.registration.processor.core.util.RegistrationExceptionMapperUtil;
import io.mosip.registration.processor.packet.storage.dto.Document;
import io.mosip.registration.processor.packet.storage.dto.FieldResponseDto;
import io.mosip.registration.processor.packet.storage.utils.FingrePrintConvertor;
import io.mosip.registration.processor.packet.storage.utils.IdSchemaUtil;
import io.mosip.registration.processor.packet.storage.utils.LegacyDataApiUtility;
import io.mosip.registration.processor.packet.storage.utils.PriorityBasedPacketManagerService;
import io.mosip.registration.processor.packet.storage.utils.Utilities;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Body;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Envelope;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Fingerprint;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Header;
import io.mosip.registration.processor.stages.legacy.data.val.dto.IdentifyPerson;
import io.mosip.registration.processor.stages.legacy.data.val.dto.IdentifyPersonResponse;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Password;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Person;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Position;
import io.mosip.registration.processor.stages.legacy.data.val.dto.Request;
import io.mosip.registration.processor.stages.legacy.data.val.dto.TransactionStatus;
import io.mosip.registration.processor.stages.legacy.data.val.dto.UsernameToken;
import io.mosip.registration.processor.status.code.RegistrationStatusCode;
import io.mosip.registration.processor.status.dto.InternalRegistrationStatusDto;
import io.mosip.registration.processor.status.dto.RegistrationStatusDto;
import io.mosip.registration.processor.status.dto.SyncRegistrationDto;
import io.mosip.registration.processor.status.dto.SyncResponseDto;
import io.mosip.registration.processor.status.entity.SyncRegistrationEntity;
import io.mosip.registration.processor.status.service.RegistrationStatusService;
import io.mosip.registration.processor.status.service.SyncRegistrationService;
import io.mosip.registration.processor.status.utilities.RegistrationUtility;

@Service
public class LegacyDataVal {
	private static Logger regProcLogger = RegProcessorLogger.getLogger(LegacyDataVal.class);

	public static final String INDIVIDUAL_TYPE_UIN = "UIN";

	private static final String ID = "mosip.commmons.packetmanager";
	private static final String VERSION = "v1";

	@Autowired
	RegistrationExceptionMapperUtil registrationExceptionMapperUtil;

	@Autowired
	private PriorityBasedPacketManagerService packetManagerService;


	@Autowired
	RegistrationStatusService<String, InternalRegistrationStatusDto, RegistrationStatusDto> registrationStatusService;

	@Autowired
	ObjectMapper mapper;

	@Autowired
	private Utilities utility;
	
	@Autowired
	private LegacyDataApiUtility legacyDataApiUtility;

	@Autowired
	private RegistrationProcessorRestClientService<Object> restApi;

	@Autowired
	private SyncRegistrationService<SyncResponseDto, SyncRegistrationDto> syncRegistrationService;

	@Autowired
	private IdSchemaUtil idSchemaUtil;

	@Autowired
	private ObjectMapper objectMapper;

	@Value("${mosip.regproc.legacydata.validator.tpi.username}")
	private String username;

	@Value("${mosip.regproc.legacydata.validator.tpi.password}")
	private String password;


	public void validate(String registrationId, InternalRegistrationStatusDto registrationStatusDto,
			LogDescription description, MessageDTO object)
			throws ApisResourceAccessException, PacketManagerException, JsonProcessingException, IOException,
			ValidationFailedException, JAXBException, NoSuchAlgorithmException,
			NumberFormatException, JSONException, DataMigrationException {

		regProcLogger.debug("validate called for registrationId {}", registrationId);

			Map<String, String> positionAndWsqMap = getBiometricsWSQFormat(registrationId, registrationStatusDto);
			String NIN = checkNINAVailableInLegacy(registrationId, positionAndWsqMap);
			if (NIN != null) {
				regProcLogger.info("NIN is present in legacy system and call for ondemand migration : {}",
						registrationId);
					MigrationRequestDto migrationRequestDto = new MigrationRequestDto();
					migrationRequestDto.setNin(NIN);
					RequestWrapper<MigrationRequestDto> requestWrapper = new RequestWrapper();
					requestWrapper.setRequest(migrationRequestDto);
					ResponseWrapper responseWrapper = (ResponseWrapper<?>) restApi
							.putApi(ApiName.MIGARTION_URL, null, "", "", requestWrapper, ResponseWrapper.class,
									null);
					regProcLogger.info("Response from migration api : {}{}", registrationId,
							JsonUtils.javaObjectToJsonString(responseWrapper));
					if (responseWrapper.getErrors() != null && responseWrapper.getErrors().size() > 0) {
						ErrorDTO error = (ErrorDTO) responseWrapper.getErrors().get(0);
						throw new DataMigrationException(error.getErrorCode(), error.getMessage());
					}
					MigrationResponse migrationResponse = objectMapper.readValue(
							JsonUtils.javaObjectToJsonString(responseWrapper.getResponse()),
							MigrationResponse.class);
					PacketDto packetDto = createOnDemandPacket(
							migrationResponse.getDemographics(), migrationResponse.getDocuments(),registrationStatusDto);
					if (packetDto != null) {
						SyncRegistrationEntity syncRegistrationEntityForOndemand = createSyncAndRegistration(packetDto,
								registrationStatusDto.getRegistrationStageName());
						if (syncRegistrationEntityForOndemand != null) {
							registrationStatusDto.setLatestTransactionStatusCode(
									RegistrationTransactionStatusCode.SUCCESS.toString());
							registrationStatusDto
									.setStatusComment(StatusUtil.ON_DEMAND_PACKET_CREATION_SUCCESS.getMessage());
							registrationStatusDto
									.setSubStatusCode(StatusUtil.ON_DEMAND_PACKET_CREATION_SUCCESS.getCode());
							registrationStatusDto.setStatusCode(RegistrationStatusCode.MERGED.toString());

							description.setMessage(
									PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE_ONDEMAND_PACKET.getMessage()
											+ " -- " + registrationId);
							description.setCode(
									PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE_ONDEMAND_PACKET.getCode());
							object.setIsValid(true);
							object.setReg_type(syncRegistrationEntityForOndemand.getRegistrationType());
							object.setRid(syncRegistrationEntityForOndemand.getRegistrationId());
							object.setWorkflowInstanceId(syncRegistrationEntityForOndemand.getWorkflowInstanceId());
							regProcLogger.info("Ondemand Packet will move forward further stages : {} ",
									registrationId);
						}
					} else {
						regProcLogger.info("Ondemand creation is failed packet going for reprocess : {} ",
								registrationId);
						registrationStatusDto
								.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.REPROCESS.toString());
						registrationStatusDto
								.setStatusComment(StatusUtil.ON_DEMAND_PACKET_CREATION_FAILED.getMessage());
						registrationStatusDto.setSubStatusCode(StatusUtil.ON_DEMAND_PACKET_CREATION_FAILED.getCode());
						registrationStatusDto.setStatusCode(RegistrationStatusCode.PROCESSING.toString());
						description.setMessage(
								PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE_ONDEMAND_PACKET.getMessage() + " -- "
										+ registrationId);
						description.setCode(PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE_ONDEMAND_PACKET.getCode());
						object.setIsValid(true);
						object.setInternalError(true);
					}

			} else {
				regProcLogger.info("NIN is not present in legacy system so proceed for new registration: {}",
						registrationId);
				registrationStatusDto
						.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.SUCCESS.toString());
				registrationStatusDto.setStatusComment(StatusUtil.LEGACY_DATA_VALIDATION_SUCCESS.getMessage());
				registrationStatusDto.setSubStatusCode(StatusUtil.LEGACY_DATA_VALIDATION_SUCCESS.getCode());
				registrationStatusDto.setStatusCode(RegistrationStatusCode.PROCESSING.toString());

				description.setMessage(
						PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE.getMessage() + " -- " + registrationId);
				description.setCode(PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE.getCode());
			}

		regProcLogger.debug("validate call ended for registrationId {}", registrationId);

	}

	private SyncRegistrationEntity createSyncAndRegistration(PacketDto packetDto, String stageName) {
		SyncRegistrationEntity syncRegistrationEntity = createSyncEntity(packetDto);
		syncRegistrationEntity = syncRegistrationService.saveSyncRegistrationEntity(syncRegistrationEntity);
		regProcLogger.info("Successfully sync the ondemand packet : {} {}", packetDto.getId());
		createRegistrationStatusEntity(stageName, syncRegistrationEntity);
		return syncRegistrationEntity;
	}

	private SyncRegistrationEntity createSyncEntity(PacketDto packetDto) {
		SyncRegistrationEntity syncRegistrationEntity = new SyncRegistrationEntity();
		syncRegistrationEntity.setRegistrationId(packetDto.getId().trim());
		syncRegistrationEntity.setLangCode("eng");
		syncRegistrationEntity.setRegistrationType(packetDto.getProcess());
		syncRegistrationEntity.setPacketHashValue("0");
		syncRegistrationEntity.setPacketSize(new BigInteger("0"));
		syncRegistrationEntity.setSupervisorStatus("APPROVED");
		syncRegistrationEntity.setPacketId(packetDto.getId());
		syncRegistrationEntity.setReferenceId(packetDto.getRefId());
		syncRegistrationEntity.setCreatedBy("MOSIP");
		syncRegistrationEntity.setCreateDateTime(LocalDateTime.now(ZoneId.of("UTC")));
		syncRegistrationEntity.setWorkflowInstanceId(RegistrationUtility.generateId());
		return syncRegistrationEntity;
	}

	private PacketDto createOnDemandPacket(DemographicsDto demographics, DocumentsDTO documents,
			InternalRegistrationStatusDto registrationStatusDto) throws ApisResourceAccessException,
			PacketManagerException,
			JsonProcessingException, IOException, NumberFormatException, JSONException {

		String registrationId = registrationStatusDto.getRegistrationId();
		String registrationType = registrationStatusDto.getRegistrationType();
		regProcLogger.info("Getting details to create ondemand packet : {}", registrationId);
		String schemaVersion = packetManagerService.getFieldByMappingJsonKey(registrationStatusDto.getRegistrationId(),
				MappingJsonConstants.IDSCHEMA_VERSION, registrationType, ProviderStageName.LEGACY_DATA);

		//Map<String, String> fieldMap = packetManagerService.getFields(registrationId,
			//	idSchemaUtil.getDefaultFields(Double.valueOf(schemaVersion)), registrationType,
			//	ProviderStageName.LEGACY_DATA);
		// TODO remove it when merging to dev
		// JSONObject demographicIdentity = new JSONObject();
		// loadDemographicIdentity(fieldMap, demographicIdentity);
		//Map<String, DocumentDto> documents=getAllDocumentsByRegId(registrationId, registrationType, demographicIdentity);

		Map<String, BiometricRecord> biometrics = getBiometrics(registrationId, registrationType);
		List<FieldResponseDto> audits = packetManagerService.getAudits(registrationId, registrationType,
				ProviderStageName.LEGACY_DATA);
		List<Map<String, String>> auditList = new ArrayList<>();
		for (FieldResponseDto dto : audits) {
			auditList.add(dto.getFields());
		}
		Map<String, String> metaInfo = packetManagerService.getMetaInfo(registrationId, registrationType,
				ProviderStageName.LEGACY_DATA);
		regProcLogger.info("successfully got  details to create ondemand packet : {}", registrationId);
		SyncRegistrationEntity regEntity = syncRegistrationService
				.findByWorkflowInstanceId(registrationStatusDto.getWorkflowInstanceId());
		PacketDto packetDto = new PacketDto();
		packetDto.setId(registrationId);
		packetDto.setSource("REGISTRATION_CLIENT");
		packetDto.setProcess("NEW");
		packetDto.setRefId(regEntity.getReferenceId());
		packetDto.setSchemaVersion(schemaVersion);
		packetDto.setSchemaJson(idSchemaUtil.getIdSchema(Double.parseDouble(schemaVersion)));
		packetDto.setFields(demographics.getFields());
		packetDto.setAudits(auditList);
		packetDto.setMetaInfo(metaInfo);
		packetDto.setDocuments(documents.getDocuments());
		packetDto.setBiometrics(biometrics);
		RequestWrapper<PacketDto> request = new RequestWrapper<>();
		request.setId(ID);
		request.setVersion(VERSION);
		request.setRequesttime(DateUtils.getUTCCurrentDateTime());
		request.setRequest(packetDto);
		ResponseWrapper responseWrapper = (ResponseWrapper<?>) restApi
				.putApi(ApiName.PACKETMANAGER_CREATE_PACKET, null, "", "", request, ResponseWrapper.class,
						null);
		if ((responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty())
				|| responseWrapper.getResponse() == null) {
			ErrorDTO error = (ErrorDTO) responseWrapper.getErrors().get(0);
			regProcLogger.info("Error while creating packet through to packet manager : {} {}", registrationId,
					error.getMessage());
		} else {
			regProcLogger.info("Successfully created packet through to packet manager : {}", registrationId);
			return packetDto;
		}
		return null;
	}

	private Map<String, String> getBiometricsWSQFormat(String registrationId,
			InternalRegistrationStatusDto registrationStatusDto)
			throws IOException, ApisResourceAccessException, PacketManagerException, JsonProcessingException,
			ValidationFailedException
	{
		
		JSONObject regProcessorIdentityJson = utility
				.getRegistrationProcessorMappingJson(MappingJsonConstants.IDENTITY);
		String individualBiometricsLabel = JsonUtil.getJSONValue(
				JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.INDIVIDUAL_BIOMETRICS),
				MappingJsonConstants.VALUE);
		List<String> modalities = new ArrayList<>();
		modalities.add("Finger");
		BiometricRecord biometricRecord = packetManagerService.getBiometrics(registrationId,
				individualBiometricsLabel,
				modalities, registrationStatusDto.getRegistrationType(),
				ProviderStageName.LEGACY_DATA);
		if (biometricRecord == null || biometricRecord.getSegments() == null
				|| biometricRecord.getSegments().isEmpty()) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					registrationId, RegistrationStatusCode.FAILED.toString() + "Biometrics are not present for packet");
			throw new ValidationFailedException(StatusUtil.LEGACY_DATA_FAILED.getMessage(),
					StatusUtil.LEGACY_DATA_FAILED.getCode());
		}
		Map<String, byte[]> isoImageMap = new HashMap<String, byte[]>();
		for (BIR bir : biometricRecord.getSegments()) {
         if(bir.getBdbInfo().getSubtype() != null) {
				String subType = String.join(" ", bir.getBdbInfo().getSubtype());
				String position = Position.getValueFromKey(subType);
				if(bir.getBdb()!=null) {
					isoImageMap.put(position, bir.getBdb());
				}
         }
		}
		
		Map<String, String> wsqFormatBiometrics = convertISOToWSQFormat(isoImageMap);
		regProcLogger.info("Converted ISO to WSQ successfully : {}", registrationId);
		return wsqFormatBiometrics;
	}

	private Map<String, String> convertISOToWSQFormat(Map<String, byte[]> isoImageMap) throws IOException {
		Map<String, String> wsqFormatBiometrics = new HashMap<String, String>();
		for (Map.Entry<String, byte[]> entry : isoImageMap.entrySet()) {
			byte[] wsqData = FingrePrintConvertor.convertIsoToWsq(entry.getValue());
			wsqFormatBiometrics.put(entry.getKey(), CryptoUtil.encodeToPlainBase64(wsqData));
		}
		return wsqFormatBiometrics;
	}

	private String checkNINAVailableInLegacy(String registrationId, Map<String, String> positionAndWsqMap)
			throws JAXBException, ApisResourceAccessException, NoSuchAlgorithmException, UnsupportedEncodingException {
		String NIN = null;
		Envelope requestEnvelope = createIdentifyPersonRequest(positionAndWsqMap);
		String request = marshalToXml(requestEnvelope);
		String response = (String) restApi.postApi(ApiName.LEGACYAPI, "", "", request, String.class,
				MediaType.TEXT_XML);
		regProcLogger.info("Response from legacy system : {}{}", registrationId,
				response);
		JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		StringReader reader = new StringReader(response);
		Envelope responseEnvelope = (Envelope) unmarshaller.unmarshal(reader);
		IdentifyPersonResponse identifyPersonResponse = responseEnvelope.getBody().getIdentifyPersonResponse();
		TransactionStatus transactionStatus = identifyPersonResponse.getReturnElement().getTransactionStatus();
		if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Ok")) {
			List<Person> persons = identifyPersonResponse.getReturnElement().getPersons();
			if (persons != null && !persons.isEmpty()) {
				if (persons.size() == 1) {
					regProcLogger.info("Single nin returned from legacy : {}", registrationId);
					NIN = persons.get(0).getNationalId();
				} else {
					regProcLogger.info("Mulitple nins returned from legacy : {}", registrationId);
				}
			} else {
				regProcLogger.info("No  nins returned from legacy : {}", registrationId);
			}
			
		} else if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Error")) {
			regProcLogger.info("Transaction status is Error : {}", registrationId);
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					registrationId,
					RegistrationStatusCode.FAILED.toString() + transactionStatus.getError().getCode()
							+ transactionStatus.getError().getMessage());
		}
		return NIN;
	}

	private Envelope createIdentifyPersonRequest(Map<String, String> positionAndWsqMap)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {

		byte[] nonceBytes = legacyDataApiUtility.generateNonce();
		String nonce = CryptoUtil.encodeToPlainBase64(nonceBytes);

		String timestamp = legacyDataApiUtility.createTimestamp();
		String timestampForDigest = legacyDataApiUtility.createTimestampForDigest(timestamp);
		String timestampForRequest = legacyDataApiUtility.createTimestampForRequest(timestamp);
		byte[] createdDigestBytes = timestampForDigest.getBytes(StandardCharsets.UTF_8);

		byte[] passwordHashBytes = legacyDataApiUtility.hashPassword(password);
		String passwordDigest = legacyDataApiUtility.generateDigest(nonceBytes, createdDigestBytes, passwordHashBytes);
		Envelope envelope = new Envelope();
		// Header
		Header header = new Header();
		UsernameToken token = new UsernameToken();
		token.setUsername(username);
		Password password = new Password();
		password.setType("PasswordDigest");
		password.setValue(passwordDigest);
		token.setPassword(password);
		token.setNonce(nonce);
		token.setCreated(timestampForRequest);
		header.setUsernameToken(token);
		envelope.setHeader(header);

		// Body
		Body body = new Body();
		IdentifyPerson identifyPerson = new IdentifyPerson();
		Request request = new Request();
		List<Fingerprint> fingerprints = new ArrayList<Fingerprint>();
		for (Map.Entry<String, String> entry : positionAndWsqMap.entrySet()) {
			Fingerprint fingerprint = new Fingerprint();
			fingerprint.setPosition(entry.getKey());
			fingerprint.setWsq(entry.getValue());
			fingerprints.add(fingerprint);
		}
		request.setFingerprints(fingerprints);
		identifyPerson.setRequest(request);
		body.setIdentifyPerson(identifyPerson);
		envelope.setBody(body);

		return envelope;
	}

	private String marshalToXml(Envelope envelope) throws JAXBException {
		JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
		Marshaller marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);

		// Use a StringWriter to capture the XML
		java.io.StringWriter sw = new java.io.StringWriter();
		marshaller.marshal(envelope, sw);
		return sw.toString();
	}

	private Map<String, DocumentDto> getAllDocumentsByRegId(String regId, String process,
			JSONObject demographicIdentity)
			throws IOException, ApisResourceAccessException, PacketManagerException, JsonProcessingException
	{
		JSONObject idJSON = demographicIdentity;
		List<Documents> applicantDocuments = new ArrayList<>();
		JSONObject docJson = utility.getRegistrationProcessorMappingJson(MappingJsonConstants.DOCUMENT);
		Map<String, DocumentDto> documents = new HashMap<String, DocumentDto>();
		for (Object doc : docJson.values()) {
			Map docMap = (LinkedHashMap) doc;
			String docValue = docMap.values().iterator().next().toString();
			HashMap<String, String> docInIdentityJson = (HashMap<String, String>) idJSON.get(docValue);
			if (docInIdentityJson != null) {
				DocumentDto documentDto = getIdDocument(regId, docValue, process);
				if (documentDto != null) {
					documents.put(docValue, documentDto);
				}
			}

		}

		return documents;
	}

	private DocumentDto getIdDocument(String registrationId, String dockey, String process)
			throws IOException, ApisResourceAccessException, PacketManagerException,
			io.mosip.kernel.core.util.exception.JsonProcessingException {

		Document document = packetManagerService.getDocument(registrationId, dockey, process,
				ProviderStageName.UIN_GENERATOR);
		if (document != null) {
			DocumentDto documentDto = new DocumentDto();
			documentDto.setDocument(document.getDocument());
			documentDto.setFormat(document.getFormat());
			documentDto.setType(document.getFormat());
			documentDto.setValue(document.getValue());
			return documentDto;
		}
		return null;
	}

	private void loadDemographicIdentity(Map<String, String> fieldMap, JSONObject demographicIdentity)
			throws IOException, JSONException {
		for (Map.Entry e : fieldMap.entrySet()) {
			if (e.getValue() != null) {
				String value = e.getValue().toString();
				if (value != null) {
					Object json = new JSONTokener(value).nextValue();
					if (json instanceof org.json.JSONObject) {
						HashMap<String, Object> hashMap = objectMapper.readValue(value, HashMap.class);
						demographicIdentity.putIfAbsent(e.getKey(), hashMap);
					} else if (json instanceof JSONArray) {
						List jsonList = new ArrayList<>();
						JSONArray jsonArray = new JSONArray(value);
						for (int i = 0; i < jsonArray.length(); i++) {
							Object obj = jsonArray.get(i);
							HashMap<String, Object> hashMap = objectMapper.readValue(obj.toString(), HashMap.class);
							jsonList.add(hashMap);
						}
						demographicIdentity.putIfAbsent(e.getKey(), jsonList);
					} else
						demographicIdentity.putIfAbsent(e.getKey(), value);
				} else
					demographicIdentity.putIfAbsent(e.getKey(), value);
			}
		}
	}

	private Map<String, BiometricRecord> getBiometrics(String registrationId, String registrationType)
			throws IOException, ApisResourceAccessException, PacketManagerException, JsonProcessingException
	{
		Map<String, BiometricRecord> biometricData = new HashMap<String, BiometricRecord>();
		JSONObject regProcessorIdentityJson = utility
				.getRegistrationProcessorMappingJson(MappingJsonConstants.IDENTITY);
		String individualBiometricsLabel = JsonUtil.getJSONValue(
				JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.INDIVIDUAL_BIOMETRICS),
				MappingJsonConstants.VALUE);
		BiometricRecord biometricRecord = packetManagerService.getBiometrics(registrationId, individualBiometricsLabel,
				registrationType,
					ProviderStageName.LEGACY_DATA_VALIDATOR);
			if (biometricRecord != null) {
				biometricData.put(individualBiometricsLabel, biometricRecord);
			}

		return biometricData;
	}

		private void createRegistrationStatusEntity(String stageName, SyncRegistrationEntity regEntity) {
			InternalRegistrationStatusDto dto = registrationStatusService.getRegistrationStatus(
					regEntity.getRegistrationId(), regEntity.getRegistrationType(), 1,
					regEntity.getWorkflowInstanceId());
			if (dto == null) {
				dto = new InternalRegistrationStatusDto();
				dto.setRetryCount(0);
			} else {
				int retryCount = dto.getRetryCount() != null ? dto.getRetryCount() + 1 : 1;
				dto.setRetryCount(retryCount);

			}
			dto.setRegistrationId(regEntity.getRegistrationId());
			dto.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.LEGACY_DATA.toString());
			dto.setLatestTransactionTimes(DateUtils.getUTCCurrentDateTime());
			dto.setRegistrationStageName(stageName);
			dto.setRegistrationType(regEntity.getRegistrationType());
			dto.setReferenceRegistrationId(null);
			dto.setStatusCode(RegistrationStatusCode.PROCESSING.toString());
			dto.setLangCode("eng");
			dto.setStatusComment(StatusUtil.ON_DEMAND_PACKET_CREATION_SUCCESS.getMessage());
			dto.setSubStatusCode(StatusUtil.ON_DEMAND_PACKET_CREATION_SUCCESS.getCode());
			dto.setReProcessRetryCount(0);
			dto.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.SUCCESS.toString());
			dto.setIsActive(true);
			dto.setCreatedBy("MOSIP");
			dto.setIsDeleted(false);
			dto.setSource(regEntity.getSource());
			dto.setIteration(1);
			dto.setWorkflowInstanceId(regEntity.getWorkflowInstanceId());

			/** Module-Id can be Both Success/Error code */
			String moduleId = PlatformSuccessMessages.RPR_LEGACY_DATA.getCode();
			String moduleName = ModuleName.LEGACY_DATA.toString();
			registrationStatusService.addRegistrationStatus(dto, moduleId, moduleName);
			regProcLogger.info("Successfully created record in registration for ondemand packet : {} ",
					regEntity.getRegistrationId());
		}

}

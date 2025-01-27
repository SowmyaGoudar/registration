package io.mosip.registration.processor.packet.storage.utils;

import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.activemq.util.ByteArrayInputStream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.http.ResponseWrapper;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.packet.dto.Identity;
import io.mosip.registration.processor.core.packet.dto.TransactionTypeDto;
import io.mosip.registration.processor.core.spi.packetmanager.PacketInfoManager;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.packet.storage.dto.ApplicantInfoDto;
import io.mosip.registration.processor.packet.storage.dto.CertificateResponse;
import io.mosip.registration.processor.packet.storage.dto.ChangePassword;
import io.mosip.registration.processor.packet.storage.dto.ChangePasswordBody;
import io.mosip.registration.processor.packet.storage.dto.ChangePasswordEnvelope;
import io.mosip.registration.processor.packet.storage.dto.ChangePasswordRequest;
import io.mosip.registration.processor.packet.storage.dto.ChangePasswordResponse;
import io.mosip.registration.processor.packet.storage.dto.GetPersonHeader;
import io.mosip.registration.processor.packet.storage.dto.GetPersonPassword;
import io.mosip.registration.processor.packet.storage.dto.GetPersonTransactionStatus;
import io.mosip.registration.processor.packet.storage.dto.GetPersonUsernameToken;

@Component
public class PasswordChangeUtility {

	private static Logger regProcLogger = RegProcessorLogger.getLogger(PasswordChangeUtility.class);

	@Value("${mosip.regproc.legacydata.validator.appid}")
	private String appId;

	@Value("${mosip.regproc.legacydata.validator.refid}")
	private String refId;

	@Value("${mosip.regproc.legacydata.validator.tpi.username}")
	private String username;

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private RegistrationProcessorRestClientService<Object> restClientService;

	@Autowired
	private LegacyDataApiUtility legacyDataApiUtility;

	/** The packet info manager. */
	@Autowired
	private PacketInfoManager<Identity, ApplicantInfoDto> packetInfoManager;

	public void updatePassword() {
		List<TransactionTypeDto> transactionTypeDtoList = packetInfoManager.getTransactionType("LEGACY");
		if (transactionTypeDtoList != null && !transactionTypeDtoList.isEmpty()) {
			TransactionTypeDto transactionTypeDto = transactionTypeDtoList.get(0);
			String oldPassword = transactionTypeDto.getDescription();
			String newPassword = generatePassword();
			boolean isChanged = changePassword(newPassword, oldPassword);
			if (isChanged) {
				transactionTypeDto.setDescription(newPassword);
				try {
					packetInfoManager.saveTransactionType(transactionTypeDto, "LEGACY", "LEGACY");
				} catch (Exception e) {
					regProcLogger.info("Exception in updating the password in DB");
				}
			}
		}


	}

	private boolean changePassword(String newPassword, String oldPassword) {
		boolean isValid = false;
		String certificate = null;
		List<String> queryParams = new ArrayList<>();
		queryParams.add("applicationId");
		queryParams.add("referenceId");

		List<Object> queryParamValues = new ArrayList<Object>();
		queryParamValues.add(appId);
		queryParamValues.add(refId);
		CertificateResponse certificateResponse = new CertificateResponse();
		ResponseWrapper<?> responseWrapper;
		try {
			responseWrapper = (ResponseWrapper<?>) restClientService.getApi(ApiName.GET_CERTIFICATE, null, queryParams,
					queryParamValues, ResponseWrapper.class);
			if (responseWrapper.getResponse() != null) {
				certificateResponse = mapper.readValue(mapper.writeValueAsString(responseWrapper.getResponse()),
						CertificateResponse.class);
				certificate = certificateResponse.getCertificate();
				String hashPwd = encryptPasswordWithCertificate(newPassword, certificate);

				ChangePasswordEnvelope changePasswordEnvelope = createChangePasswordRequest(hashPwd, oldPassword);
				String changePasswordRequest = marshalToXml(changePasswordEnvelope);
				regProcLogger.debug("Request to legacy system : {}", changePasswordRequest);
				String response = (String) restClientService.postApi(ApiName.LEGACYAPI, "", "", changePasswordRequest,
						String.class, MediaType.TEXT_XML);
				regProcLogger.info("Response from legacy system : {}{}", response);
				JAXBContext jaxbContext = JAXBContext.newInstance(ChangePasswordEnvelope.class);
				Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
				StringReader reader = new StringReader(response);
				ChangePasswordEnvelope responseEnvelope = (ChangePasswordEnvelope) unmarshaller.unmarshal(reader);
				ChangePasswordResponse changePasswordResponse = responseEnvelope.getBody().getChangePasswordResponse();
				GetPersonTransactionStatus transactionStatus = changePasswordResponse.getReturnElement()
						.getTransactionStatus();
				if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Ok")) {
					isValid = true;
				} else if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Error")) {
					regProcLogger.info("Transaction status is Error for changeing the password");
				}
			} else if (responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty()) {
				regProcLogger.error("error occured while getting certificate.",
						responseWrapper.getErrors().iterator().next().toString());
			}

		} catch (Exception e) {
			regProcLogger.error("error in changing the password" + e.getMessage());
		}
		return isValid;
	}

	private ChangePasswordEnvelope createChangePasswordRequest(String encryptedPassword, String oldPassword)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {

		byte[] nonceBytes = legacyDataApiUtility.generateNonce();
		String nonce = CryptoUtil.encodeToPlainBase64(nonceBytes);

		String timestamp = legacyDataApiUtility.createTimestamp();
		String timestampForDigest = legacyDataApiUtility.createTimestampForDigest(timestamp);
		String timestampForRequest = timestamp;
		byte[] createdDigestBytes = timestampForDigest.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

		byte[] passwordHashBytes = sha1.digest(oldPassword.getBytes("UTF-8"));
		String passwordDigest = legacyDataApiUtility.generateDigest(nonceBytes, createdDigestBytes, passwordHashBytes);
		ChangePasswordEnvelope envelope = new ChangePasswordEnvelope();
		// Header
		GetPersonHeader header = new GetPersonHeader();
		GetPersonUsernameToken token = new GetPersonUsernameToken();
		token.setUsername(username);
		GetPersonPassword password = new GetPersonPassword();
		password.setType("PasswordDigest");
		password.setValue(passwordDigest);
		token.setPassword(password);
		token.setNonce(nonce);
		token.setCreated(timestampForRequest);
		header.setUsernameToken(token);
		envelope.setHeader(header);

		// Body
		ChangePasswordBody body = new ChangePasswordBody();
		ChangePassword changePassword = new ChangePassword();
		ChangePasswordRequest request = new ChangePasswordRequest();
		request.setNewPassword(encryptedPassword);
		changePassword.setRequest(request);
		body.setChangePassword(changePassword);
		envelope.setBody(body);
		return envelope;
	}

	private String marshalToXml(ChangePasswordEnvelope envelope) throws JAXBException {
		JAXBContext jaxbContext = JAXBContext.newInstance(ChangePasswordEnvelope.class);
		Marshaller marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);

		// Use a StringWriter to capture the XML
		java.io.StringWriter sw = new java.io.StringWriter();
		marshaller.marshal(envelope, sw);
		return sw.toString();
	}

	public String generatePassword() {
		SecureRandom random = new SecureRandom();

		// Define the character sets
		String specialCharacters = "@!#_+$%*";
		String digits = "0123456789";
		String lowercase = "abcdefghijklmnopqrstuvwxyz";
		String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

		// Initial password list, ensuring it contains at least one character from each
		// required set
		List<Character> passwordList = new ArrayList<>();
		passwordList.add(specialCharacters.charAt(random.nextInt(specialCharacters.length()))); // Special character
		passwordList.add(digits.charAt(random.nextInt(digits.length()))); // Digit
		passwordList.add(lowercase.charAt(random.nextInt(lowercase.length()))); // Lowercase letter
		passwordList.add(uppercase.charAt(random.nextInt(uppercase.length()))); // Uppercase letter

		// Adding random characters (total length 6 to 10, here we are adding 5 more)
		String allCharacters = digits + lowercase + uppercase + specialCharacters;
		for (int i = 0; i < 5; i++) {
			passwordList.add(allCharacters.charAt(random.nextInt(allCharacters.length())));
		}

		// Shuffle the list to ensure randomness
		Collections.shuffle(passwordList, random);

		// Convert the list to a string
		StringBuilder password = new StringBuilder();
		for (Character ch : passwordList) {
			password.append(ch);
		}

		return password.toString();
	}

	private String encryptPasswordWithCertificate(String rawPassword, String certificateFilePath)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, CertificateException {
		// Convert the raw password to bytes
		byte[] message = rawPassword.getBytes(StandardCharsets.UTF_8);

		// Load the public key from the certificate
		RSAPublicKey publicKey = loadPublicKeyFromCertificate(certificateFilePath);

		// Encrypt the password with the public key
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] ciphertext = cipher.doFinal(message);
		// Encode the ciphertext in Base64 and return
		return Base64.getEncoder().encodeToString(ciphertext);
	}

	private RSAPublicKey loadPublicKeyFromCertificate(String certificate) throws CertificateException {

		InputStream inputStream = new ByteArrayInputStream(certificate.getBytes());
		// Get the CertificateFactory instance
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

		// Load the certificate
		Certificate cert = certFactory.generateCertificate(inputStream);

		// Extract the public key from the certificate
		PublicKey publicKey = cert.getPublicKey();
		return (RSAPublicKey) publicKey;
	}
}

package io.mosip.registration.processor.packet.storage.utils;

import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;

import org.jnbis.api.Jnbis;

import io.mosip.biometrics.util.ConvertRequestDto;
import io.mosip.biometrics.util.finger.FingerBDIR;
import io.mosip.imagedecoder.model.DecoderRequestInfo;
import io.mosip.imagedecoder.model.DecoderResponseInfo;
import io.mosip.imagedecoder.model.Response;
import io.mosip.imagedecoder.openjpeg.OpenJpegDecoder;
import io.mosip.imagedecoder.spi.IImageDecoderApi;

public class FingrePrintConvertor {


	// Method to convert ISO to WSQ

	public static byte[] convertIsoToWsq(byte[] isoBytes) throws IOException {
		ConvertRequestDto req = new ConvertRequestDto();
		req.setInputBytes(isoBytes);
		req.setImageType(0);
		req.setPurpose("REGISTRATION");
		req.setVersion("ISO19794_4_2011");
		FingerBDIR fingerBDIR = getFingerBDIRISO19794_4_2011(req.getInputBytes(), req.getOnlyImageInformation());
		byte[] isoData = fingerBDIR.getRepresentation().getRepresentationBody().getImageData().getImage();
		DecoderRequestInfo requestInfo = new DecoderRequestInfo();
		requestInfo.setImageData(isoData);
		requestInfo.setBufferedImage(true);
		IImageDecoderApi decoder = new OpenJpegDecoder();
		Response<DecoderResponseInfo> info = decoder.decode(requestInfo);
		DecoderResponseInfo decoderResponseInfo = info.getResponse();
		BufferedImage fingerprintImage = info.getResponse().getBufferedImage();

		/*
		 * Step 2: Convert the BufferedImage to FingerprintTemplate Convert
		 * BufferedImage to raw pixel data byte array
		 */
		byte[] imageBytes = ((DataBufferByte) fingerprintImage.getRaster().getDataBuffer()).getData();

		/*
		 * Step 3: Compress to WSQ format using WSQEncoder Using the WSQEncoder from
		 * JMRTD
		 */
		float compressionRatio = 0.75f;
		ByteArrayOutputStream wsqOutputStream = new ByteArrayOutputStream();
		io.mosip.registration.processor.packet.storage.utils.WSQEncoder.encode(wsqOutputStream,
				new Bitmap(imageBytes, fingerprintImage.getWidth(), fingerprintImage.getHeight(), 500,
						Integer.parseInt(decoderResponseInfo.getImageDepth()),
						Integer.parseInt(decoderResponseInfo.getImageLossless())),
				compressionRatio);

		/* Return the WSQ byte array */
		return wsqOutputStream.toByteArray();

	}

	private static FingerBDIR getFingerBDIRISO19794_4_2011(byte[] isoData, int onlyImageInformation)
			throws IOException {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(isoData);
				DataInputStream inputStream = new DataInputStream(bais);) {
			FingerBDIR fingerBDIR = null;
			if (onlyImageInformation == 1)
				fingerBDIR = new FingerBDIR(inputStream, true);
			else
				fingerBDIR = new FingerBDIR(inputStream);
			// LOGGER.info("fingerBDIR :: ", fingerBDIR);
			return fingerBDIR;
		}
	}

	public static void getImage(byte[] wsqData) {
		try {
			// Decode the WSQ byte array to a Bitmap
			org.jnbis.api.model.Bitmap bitmap = Jnbis.wsq().decode(wsqData).asBitmap();

			// Create BufferedImage from Bitmap data
			BufferedImage image = new BufferedImage(bitmap.getWidth(), bitmap.getHeight(),
					BufferedImage.TYPE_BYTE_GRAY);
			image.getRaster().setDataElements(0, 0, bitmap.getWidth(), bitmap.getHeight(), bitmap.getPixels());

			// Save the BufferedImage to an output file
			String outputImagePath = "E:\\\\image16.png"; // Path for the output
															// image

			ImageIO.write(image, "png", new File(outputImagePath));

			System.out.println("Image saved successfully at: " + outputImagePath);
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Failed to convert WSQ to image.");
		}

	}
}
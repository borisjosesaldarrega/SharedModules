package com.liskovsoft.appupdatechecker2.security;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Validates update metadata before an APK is offered to Android's installer.
 *
 * <p>This class has no downloader or installer side effects. DZTube keeps the
 * updater disabled until the caller also verifies the downloaded APK package
 * and signing certificate with Android PackageManager.</p>
 */
public final class UpdateArtifactPolicy {
    private static final String SHA_256_PATTERN = "(?i)[0-9a-f]{64}";

    private UpdateArtifactPolicy() {
    }

    public static void validateMetadata(
            String manifestUrl,
            String apkUrl,
            String expectedSha256,
            String expectedCertificateSha256,
            String expectedPackage,
            String actualPackage,
            long installedVersionCode,
            long offeredVersionCode,
            int deviceSdk,
            int minimumSdk,
            String deviceAbi,
            String offeredAbi) {
        requireHttps(manifestUrl, "manifest");
        requireHttps(apkUrl, "APK");
        requireSha256(expectedSha256, "APK");
        requireSha256(expectedCertificateSha256, "certificate");

        if (isBlank(expectedPackage) || !expectedPackage.equals(actualPackage)) {
            throw new IllegalArgumentException("Update package does not match DZTube");
        }
        if (offeredVersionCode <= installedVersionCode) {
            throw new IllegalArgumentException("Update version must be newer than the installed version");
        }
        if (minimumSdk > deviceSdk) {
            throw new IllegalArgumentException("Update requires a newer Android SDK");
        }
        if (isBlank(deviceAbi) || isBlank(offeredAbi) || !deviceAbi.equalsIgnoreCase(offeredAbi)) {
            throw new IllegalArgumentException("Update ABI is incompatible with this device");
        }
    }

    public static boolean verifySha256(InputStream input, String expectedSha256) throws IOException {
        requireSha256(expectedSha256, "APK");

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return toHex(digest.digest()).equals(expectedSha256.toLowerCase(Locale.US));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static void requireHttps(String value, String label) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(label + " URL is missing");
        }

        try {
            URI uri = new URI(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || isBlank(uri.getHost()) || uri.getUserInfo() != null) {
                throw new IllegalArgumentException(label + " URL must use HTTPS without embedded credentials");
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(label + " URL is invalid", e);
        }
    }

    private static void requireSha256(String value, String label) {
        if (value == null || !value.matches(SHA_256_PATTERN)) {
            throw new IllegalArgumentException(label + " SHA-256 must contain 64 hexadecimal characters");
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.US, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}

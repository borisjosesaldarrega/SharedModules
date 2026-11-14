package com.liskovsoft.appupdatechecker2.security;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class UpdateArtifactPolicyTest {
    private static final String HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Test
    public void acceptsCompatibleHttpsMetadata() {
        UpdateArtifactPolicy.validateMetadata(
                "https://example.org/releases/manifest.json",
                "https://example.org/releases/dztube.apk",
                HASH,
                HASH,
                "lab.m300max.smarttube",
                "lab.m300max.smarttube",
                10,
                11,
                30,
                21,
                "armeabi-v7a",
                "armeabi-v7a");
    }

    @Test
    public void rejectsHttpAndEmbeddedCredentials() {
        assertIllegalArgument(() -> UpdateArtifactPolicy.validateMetadata(
                "http://example.org/manifest.json", "https://example.org/dztube.apk", HASH, HASH,
                "lab.m300max.smarttube", "lab.m300max.smarttube", 10, 11, 30, 21,
                "armeabi-v7a", "armeabi-v7a"));

        assertIllegalArgument(() -> UpdateArtifactPolicy.validateMetadata(
                "https://user:pass@example.org/manifest.json", "https://example.org/dztube.apk", HASH, HASH,
                "lab.m300max.smarttube", "lab.m300max.smarttube", 10, 11, 30, 21,
                "armeabi-v7a", "armeabi-v7a"));
    }

    @Test
    public void rejectsWrongPackageVersionSdkAbiAndHash() {
        assertRejected("other.package", 11, 21, "armeabi-v7a", HASH);
        assertRejected("lab.m300max.smarttube", 10, 21, "armeabi-v7a", HASH);
        assertRejected("lab.m300max.smarttube", 11, 31, "armeabi-v7a", HASH);
        assertRejected("lab.m300max.smarttube", 11, 21, "arm64-v8a", HASH);
        assertRejected("lab.m300max.smarttube", 11, 21, "armeabi-v7a", "not-a-hash");
    }

    @Test
    public void verifiesDownloadedBytes() throws Exception {
        byte[] bytes = "DZTube".getBytes(StandardCharsets.UTF_8);
        String correct = "6a9223b2f0b9685f619025d4bc021a92e29f53321398bc699ec96888ff84fb76";

        assertTrue(UpdateArtifactPolicy.verifySha256(new ByteArrayInputStream(bytes), correct));
        assertFalse(UpdateArtifactPolicy.verifySha256(new ByteArrayInputStream(bytes), HASH));
    }

    private static void assertRejected(String actualPackage, long offeredVersion, int minSdk,
                                       String offeredAbi, String hash) {
        assertIllegalArgument(() -> UpdateArtifactPolicy.validateMetadata(
                "https://example.org/manifest.json", "https://example.org/dztube.apk", hash, HASH,
                "lab.m300max.smarttube", actualPackage, 10, offeredVersion, 30, minSdk,
                "armeabi-v7a", offeredAbi));
    }

    private static void assertIllegalArgument(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected rejection.
        }
    }
}

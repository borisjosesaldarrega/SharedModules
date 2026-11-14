package com.liskovsoft.sharedutils.prefs;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.liskovsoft.sharedutils.mylogger.Log;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Encrypts account credentials with an app-specific Android Keystore key. */
final class SecureDataCodec {
    private static final String TAG = SecureDataCodec.class.getSimpleName();
    private static final String PREFIX = "DZSEC1:";

    private SecureDataCodec() {
    }

    static boolean isSupported() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    static boolean isEncrypted(String value) {
        return value != null && value.startsWith(PREFIX);
    }

    static String encrypt(Context context, String plainText) {
        if (plainText == null || !isSupported()) {
            return null;
        }

        try {
            return Api23.encrypt(context, plainText);
        } catch (Exception e) {
            Log.e(TAG, "Unable to encrypt local account data", e);
            return null;
        }
    }

    static String decrypt(Context context, String encoded) {
        if (encoded == null || !isEncrypted(encoded) || !isSupported()) {
            return null;
        }

        try {
            return Api23.decrypt(context, encoded);
        } catch (Exception e) {
            Log.e(TAG, "Unable to decrypt local account data", e);
            return null;
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static final class Api23 {
        private static final String KEYSTORE = "AndroidKeyStore";
        private static final String TRANSFORMATION = "AES/GCM/NoPadding";

        static String encrypt(Context context, String plainText) throws Exception {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(context));
            cipher.updateAAD(context.getPackageName().getBytes(StandardCharsets.UTF_8));
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP) + ":" +
                    Base64.encodeToString(encrypted, Base64.NO_WRAP);
        }

        static String decrypt(Context context, String encoded) throws Exception {
            String[] parts = encoded.substring(PREFIX.length()).split(":", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid encrypted account record");
            }

            byte[] iv = Base64.decode(parts[0], Base64.NO_WRAP);
            byte[] encrypted = Base64.decode(parts[1], Base64.NO_WRAP);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(context), new GCMParameterSpec(128, iv));
            cipher.updateAAD(context.getPackageName().getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        }

        private static SecretKey getOrCreateKey(Context context) throws Exception {
            String alias = context.getPackageName() + ".dztube.account.v1";
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            SecretKey existing = (SecretKey) keyStore.getKey(alias, null);
            if (existing != null) {
                return existing;
            }

            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
            generator.init(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build());
            return generator.generateKey();
        }
    }
}

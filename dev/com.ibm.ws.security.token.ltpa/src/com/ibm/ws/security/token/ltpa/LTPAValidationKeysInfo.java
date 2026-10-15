/*******************************************************************************
 * Copyright (c) 2023, 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.security.token.ltpa.pqc.LTPAPQCKeys;

/**
 * Container for LTPA validation keys, supporting classical (LTPA2), PQC (LTPA3), and hybrid keys.
 */
public class LTPAValidationKeysInfo {
    private static final TraceComponent tc = Tr.register(LTPAValidationKeysInfo.class);

    String filename = null;
    private byte[] secretKey = null;
    private byte[] privateKey = null;
    private byte[] publicKey = null;
    private byte[] mldsaPrivateKey = null;
    private byte[] mldsaPublicKey = null;
    private PrivateKey privateKeyObj = null;
    private PublicKey publicKeyObj = null;
    private LTPAPrivateKey ltpaPrivateKey = null;
    private LTPAPublicKey ltpaPublicKey = null;
    private LTPAPQCKeys pqcKeys = null;
    private LTPAHybridKeys hybridKeys = null;
    OffsetDateTime validUntilDateOdt = null;

    LTPAValidationKeysInfo(String filename, byte[] secretKey, byte[] privateKey, byte[] publicKey, OffsetDateTime validUntilDateOdt) {
        this.filename = filename;
        this.secretKey = secretKey;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.validUntilDateOdt = validUntilDateOdt;

        // Auto-detect standard (ASN.1 DER sequence 0x30) vs custom legacy LTPA encoding
        boolean isStandardPub = publicKey != null && publicKey.length > 0 && publicKey[0] == 0x30;
        boolean isStandardPriv = privateKey != null && privateKey.length > 0 && privateKey[0] == 0x30;

        if (isStandardPub) {
            try {
                System.out.println("DEBUG: Trying to recreate keys using standard encoding.");
                KeyFactory kf = KeyFactory.getInstance("RSA");
                publicKeyObj = kf.generatePublic(new X509EncodedKeySpec(publicKey));
                if (privateKey != null && isStandardPriv) {
                    privateKeyObj = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
                }
            } catch (Exception e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Error generating standard RSA validation keys for " + filename + ": " + e.getMessage());
                }
            }
        } else {
            System.out.println("DEBUG: Trying to recreate keys using custom encoding.");
            if (privateKey != null) {
                ltpaPrivateKey = new LTPAPrivateKey(privateKey);
                privateKeyObj = ltpaPrivateKey;
            }
            if (publicKey != null) {
                ltpaPublicKey = new LTPAPublicKey(publicKey);
                publicKeyObj = ltpaPublicKey;
            }
        }
    }

    LTPAValidationKeysInfo(String filename, byte[] secretKey, byte[] mldsaPrivateKey, byte[] mldsaPublicKey, OffsetDateTime validUntilDateOdt, boolean pqc) {
        this.filename = filename;
        this.secretKey = secretKey;
        this.mldsaPrivateKey = mldsaPrivateKey;
        this.mldsaPublicKey = mldsaPublicKey;
        this.validUntilDateOdt = validUntilDateOdt;
    }

    public String getFilename() {
        return filename;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public byte[] getprivateKey() {
        return privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public LTPAPrivateKey getLTPAPrivateKey() {
        return ltpaPrivateKey;
    }

    public LTPAPublicKey getLTPAPublicKey() {
        return ltpaPublicKey;
    }

    public PrivateKey getPrivateKeyObject() {
        return privateKeyObj;
    }

    public PublicKey getPublicKeyObject() {
        return publicKeyObj;
    }

    public byte[] getMLDSAPrivateKey() {
        return mldsaPrivateKey;
    }

    public byte[] getMLDSAPublicKey() {
        return mldsaPublicKey;
    }

    /**
     * Sets the PQC keys for LTPA3 token validation (legacy support).
     *
     * @param pqcKeys The PQC keys (RSA + ML-KEM)
     * @deprecated Use {@link #setHybridKeys(LTPAHybridKeys)} instead
     */
    @Deprecated
    public void setPQCKeys(LTPAPQCKeys pqcKeys) {
        this.pqcKeys = pqcKeys;
    }

    /**
     * Gets the PQC keys for LTPA3 token validation (legacy support).
     *
     * @return The PQC keys, or null if not set
     * @deprecated Use {@link #getHybridKeys()} instead
     */
    @Deprecated
    public LTPAPQCKeys getPQCKeys() {
        return pqcKeys;
    }

    /**
     * Sets the hybrid keys for LTPA3 token validation.
     *
     * @param hybridKeys The hybrid keys (RSA + ML-DSA + ML-KEM)
     */
    public void setHybridKeys(LTPAHybridKeys hybridKeys) {
        this.hybridKeys = hybridKeys;
    }

    /**
     * Gets the hybrid keys for LTPA3 token validation.
     *
     * @return The hybrid keys, or null if not set
     */
    public LTPAHybridKeys getHybridKeys() {
        return hybridKeys;
    }

    // Check if the validUntilDate0dt has already passed.
    // If so, then they key is expired, and will return true with a warning message.
    // Otherwise, the key is valid and will return false.
    // If the validUntilDateOdt is null, then the key is forever valid and will return false.
    public boolean isValidUntilDateExpired() {
        if (validUntilDateOdt == null) // If not specified, then it is forever valid.
            return false;

        OffsetDateTime currentTime = OffsetDateTime.now(validUntilDateOdt.getOffset());

        if (validUntilDateOdt.isBefore(currentTime)) {
            Tr.warning(tc, "LTPA_VALIDATION_KEYS_VALID_UNTIL_DATE_IS_IN_THE_PAST", validUntilDateOdt, filename);
            return true;
        } else {
            return false;
        }
    }
}

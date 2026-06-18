package io.xlogistx.opsec.ssl;

import java.security.GeneralSecurityException;

/**
 * Thrown by {@link IdentityStore#reload()} when a loaded leaf certificate is
 * outside its validity window (expired or not yet valid) and validity checking is
 * enabled. Because reload() builds the new identity set before swapping, throwing
 * this leaves the previously-loaded identities serving unchanged.
 */
public class CertificateValidityException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    public CertificateValidityException(String message) {
        super(message);
    }

    public CertificateValidityException(String message, Throwable cause) {
        super(message, cause);
    }
}

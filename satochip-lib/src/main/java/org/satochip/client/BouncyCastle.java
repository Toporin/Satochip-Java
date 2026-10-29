package org.satochip.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

/**
 * The BouncyCastle provider used by the library.
 *
 * <p>The library passes this instance directly to the JCA {@code getInstance()} calls instead of
 * looking up a provider by the name "BC", so nothing has to be registered with
 * {@link java.security.Security} beforehand. This matters on Android, where the platform registers
 * its own reduced BouncyCastle under the name "BC" (without ECDH, SHA256 or X.509), and on desktop
 * JVMs, where nothing is registered under that name by default.</p>
 */
public final class BouncyCastle {

    /** The provider instance, shared by the whole library. It is never added to the Security registry. */
    public static final Provider PROVIDER = new BouncyCastleProvider();

    private BouncyCastle() {
    }
}
